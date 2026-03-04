use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use codex_protocol::protocol::AutoReviewRequest;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ReviewFinding;
use codex_protocol::protocol::ReviewOutputEvent;
use codex_protocol::protocol::ReviewRequest;
use codex_protocol::protocol::ReviewTarget;
use codex_protocol::protocol::WarningEvent;
use codex_protocol::request_user_input::RequestUserInputArgs;
use codex_protocol::request_user_input::RequestUserInputQuestion;
use codex_protocol::request_user_input::RequestUserInputQuestionOption;
use codex_protocol::request_user_input::RequestUserInputResponse;
use codex_protocol::user_input::UserInput;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::codex::Session;
use crate::codex::TurnContext;
use crate::codex::run_turn;
use crate::review_prompts::AUTO_REVIEW_STAGED_PROMPT;
use crate::review_prompts::resolve_review_request;
use crate::state::TaskKind;

use super::SessionTask;
use super::SessionTaskContext;
use super::review::exit_review_mode;
use super::review::run_review_delegate;

const DEFAULT_MAX_ITERATIONS: u8 = 20;
const MAX_ITERATIONS_CAP: u8 = 20;
const DEFAULT_MAX_FINDINGS_PER_ITERATION: usize = 50;
const DEFAULT_STAGNATION_ROUNDS: u8 = 2;
const BASE_VALIDATION_COMMAND: &str = "git diff --check";
const MAX_SCOPE_GROUP_FANOUT: usize = 6;
const MAX_FILES_PER_SCOPE_GROUP: usize = 10;
const SOFT_SHELL_COMMAND_BUDGET: usize = 16;
const MAX_BROADEN_FALLBACK_COMMANDS: usize = 1;
const SENSITIVE_FINDINGS_QUESTION_ID: &str = "auto_review_sensitive_findings_action";
const SENSITIVE_FINDINGS_OPTION_APPLY_ALL: &str = "Apply all findings";
const SENSITIVE_FINDINGS_OPTION_SKIP_SECURITY: &str = "Skip security/auth findings";
const SENSITIVE_FINDINGS_OPTION_SKIP_BEHAVIOR: &str = "Skip behavior-changing findings";
const SENSITIVE_FINDINGS_OPTION_SKIP_BOTH: &str = "Skip both sensitive categories";
const SENSITIVE_FINDINGS_OPTION_CANCEL: &str = "Cancel auto-review";
const SECURITY_AUTH_KEYWORDS: &[&str] = &[
    "auth",
    "auth token",
    "authentication",
    "authorization",
    "oauth",
    "jwt",
    "api token",
    "bearer token",
    "session token",
    "credential",
    "secret",
    "password",
    "permission",
    "security",
    "csrf",
    "xss",
    "sql injection",
    "command injection",
    "prompt injection",
    "code injection",
    "ssrf",
];
const BEHAVIOR_CHANGE_KEYWORDS: &[&str] = &[
    "breaking",
    "behavior change",
    "change behavior",
    "backward compatibility",
    "backwards compatibility",
    "incompatible",
    "api change",
    "contract change",
    "semantic change",
    "migration required",
    "default behavior",
];

pub(crate) struct AutoReviewTask {
    request: AutoReviewRequest,
}

impl AutoReviewTask {
    pub(crate) fn new(request: AutoReviewRequest) -> Self {
        Self { request }
    }
}

#[async_trait]
impl SessionTask for AutoReviewTask {
    fn kind(&self) -> TaskKind {
        TaskKind::AutoReview
    }

    async fn run(
        self: Arc<Self>,
        session: Arc<SessionTaskContext>,
        ctx: Arc<TurnContext>,
        _input: Vec<UserInput>,
        cancellation_token: CancellationToken,
    ) -> Option<String> {
        let sess = session.clone_session();
        let max_iterations = self
            .request
            .max_iterations
            .unwrap_or(DEFAULT_MAX_ITERATIONS)
            .clamp(1, MAX_ITERATIONS_CAP);
        let max_findings_per_iteration = self
            .request
            .max_findings_per_iteration
            .map(usize::from)
            .unwrap_or(DEFAULT_MAX_FINDINGS_PER_ITERATION)
            .max(1);
        let prompt_for_sensitive_findings =
            self.request.prompt_for_sensitive_findings.unwrap_or(false);
        let stagnation_rounds = self
            .request
            .stagnation_rounds
            .unwrap_or(DEFAULT_STAGNATION_ROUNDS)
            .max(1);
        let validation_commands = collect_validation_commands(
            self.request.validation_commands.clone().unwrap_or_default(),
        );

        let mut previous_signature: Option<String> = None;
        let mut unchanged_rounds: u8 = 0;
        let mut iteration: u8 = 1;

        while iteration <= max_iterations && !cancellation_token.is_cancelled() {
            let target = iteration_target(&self.request.target, iteration);
            let unresolved_review_request = ReviewRequest {
                target,
                user_facing_hint: None,
            };
            let resolved =
                match resolve_review_request(unresolved_review_request, ctx.cwd.as_path()) {
                    Ok(resolved) => resolved,
                    Err(err) => {
                        return Some(format!(
                            "Auto-review failed before iteration {iteration}: {err}"
                        ));
                    }
                };

            let review_request = ReviewRequest {
                target: resolved.target.clone(),
                user_facing_hint: Some(resolved.user_facing_hint.clone()),
            };
            sess.send_event(&ctx, EventMsg::EnteredReviewMode(review_request))
                .await;

            let review_output = run_review_delegate(
                session.clone(),
                ctx.clone(),
                vec![UserInput::Text {
                    text: resolved.prompt,
                    text_elements: Vec::new(),
                }],
                cancellation_token.child_token(),
            )
            .await;

            exit_review_mode(sess.clone(), review_output.clone(), ctx.clone()).await;

            let Some(review_output) = review_output else {
                return Some(format!(
                    "Auto-review stopped at iteration {iteration}: review delegate was interrupted."
                ));
            };

            if review_output.findings.is_empty() {
                return Some(format!(
                    "Auto-review completed in {iteration} iteration(s): no findings remain."
                ));
            }

            let signature = findings_signature(&review_output);
            if let Some(previous) = previous_signature.as_ref() {
                if previous == &signature {
                    unchanged_rounds = unchanged_rounds.saturating_add(1);
                } else {
                    unchanged_rounds = 0;
                }
            }
            previous_signature = Some(signature);

            if unchanged_rounds >= stagnation_rounds {
                return Some(format!(
                    "Auto-review stopped after {iteration} iteration(s): findings stagnated for {unchanged_rounds} round(s)."
                ));
            }

            let ranked_findings = sort_findings(&review_output.findings);
            let selected_findings = take_top_findings(&ranked_findings, max_findings_per_iteration);
            let selected_findings = if prompt_for_sensitive_findings {
                match maybe_filter_sensitive_findings(
                    sess.clone(),
                    ctx.clone(),
                    iteration,
                    selected_findings,
                    &ranked_findings,
                    max_findings_per_iteration,
                )
                .await
                {
                    SensitiveFilteringResult::Proceed(findings) => findings,
                    SensitiveFilteringResult::Cancelled => {
                        return Some(format!(
                            "Auto-review stopped at iteration {iteration}: sensitive findings prompt was cancelled."
                        ));
                    }
                    SensitiveFilteringResult::AllSkipped => {
                        return Some(format!(
                            "Auto-review stopped at iteration {iteration}: all selected findings were skipped by user choice."
                        ));
                    }
                }
            } else {
                selected_findings
            };
            let scope_groups = build_fix_scope_groups(&selected_findings);
            debug!(
                iteration,
                findings = selected_findings.len(),
                scope_groups = scope_groups.len(),
                parallel_tool_calls = ctx.model_info.supports_parallel_tool_calls,
                "auto-review prepared finding-led scope groups"
            );
            let fix_prompt = build_fix_prompt(
                iteration,
                max_iterations,
                &selected_findings,
                &validation_commands,
                ctx.config.auto_fix_prompt.as_deref(),
                ctx.model_info.supports_parallel_tool_calls,
                &scope_groups,
            );
            let fix_turn_result = run_turn(
                sess.clone(),
                ctx.clone(),
                vec![UserInput::Text {
                    text: fix_prompt,
                    text_elements: Vec::new(),
                }],
                None,
                cancellation_token.child_token(),
            )
            .await;

            if cancellation_token.is_cancelled() {
                break;
            }

            if fix_turn_result.is_none() {
                return Some(format!(
                    "Auto-review stopped at iteration {iteration}: fix turn did not complete."
                ));
            }

            if iteration == max_iterations {
                return Some(format!(
                    "Auto-review loop complete. {max_iterations} iterations done."
                ));
            }

            let message = format!(
                "Auto-review iteration {iteration}/{max_iterations} completed; rerunning reviewer."
            );
            sess.send_event(&ctx, EventMsg::Warning(WarningEvent { message }))
                .await;

            iteration = iteration.saturating_add(1);
        }

        if cancellation_token.is_cancelled() {
            Some("Auto-review interrupted by user.".to_string())
        } else {
            Some(format!(
                "Auto-review loop complete. {max_iterations} iterations done."
            ))
        }
    }
}

fn iteration_target(initial: &ReviewTarget, iteration: u8) -> ReviewTarget {
    if iteration == 1 {
        return initial.clone();
    }

    match initial {
        ReviewTarget::Commit { .. } => ReviewTarget::UncommittedChanges,
        _ => {
            if staged_scope_uses_uncommitted_follow_up(initial) {
                ReviewTarget::UncommittedChanges
            } else {
                initial.clone()
            }
        }
    }
}

fn staged_scope_uses_uncommitted_follow_up(initial: &ReviewTarget) -> bool {
    match initial {
        ReviewTarget::Custom { instructions } => instructions.trim() == AUTO_REVIEW_STAGED_PROMPT,
        _ => false,
    }
}

fn collect_validation_commands(user_commands: Vec<String>) -> Vec<String> {
    let user_commands = user_commands
        .into_iter()
        .map(|command| command.trim().to_string())
        .filter(|command| !command.is_empty())
        .collect::<Vec<_>>();

    let has_cached_check = user_commands.iter().any(|command| {
        command.contains("git diff --cached --check")
            || command.contains("git diff --staged --check")
    });
    if has_cached_check {
        return user_commands;
    }

    let mut commands = vec![BASE_VALIDATION_COMMAND.to_string()];
    commands.extend(user_commands);
    commands
}

fn sort_findings(findings: &[ReviewFinding]) -> Vec<ReviewFinding> {
    let mut selected = findings.to_vec();
    selected.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| right.confidence_score.total_cmp(&left.confidence_score))
    });
    selected
}

fn take_top_findings(findings: &[ReviewFinding], max_findings: usize) -> Vec<ReviewFinding> {
    findings.iter().take(max_findings).cloned().collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SensitiveFindingsDecision {
    ApplyAll,
    SkipSecurity,
    SkipBehavior,
    SkipBoth,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SensitiveFindingFlags {
    security_auth: bool,
    behavior_change: bool,
}

enum SensitiveFilteringResult {
    Proceed(Vec<ReviewFinding>),
    Cancelled,
    AllSkipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixScopeGroup {
    module: String,
    finding_indices: Vec<usize>,
    files: Vec<String>,
}

async fn maybe_filter_sensitive_findings(
    sess: Arc<Session>,
    ctx: Arc<TurnContext>,
    iteration: u8,
    selected_findings: Vec<ReviewFinding>,
    ranked_findings: &[ReviewFinding],
    max_findings_per_iteration: usize,
) -> SensitiveFilteringResult {
    let (security_auth_count, behavior_change_count) = sensitive_finding_counts(&selected_findings);
    if security_auth_count == 0 && behavior_change_count == 0 {
        return SensitiveFilteringResult::Proceed(selected_findings);
    }

    let decision = prompt_for_sensitive_findings(
        sess,
        ctx,
        iteration,
        security_auth_count,
        behavior_change_count,
    )
    .await;
    if decision == SensitiveFindingsDecision::Cancel {
        return SensitiveFilteringResult::Cancelled;
    }

    let filtered = findings_for_iteration_after_decision(
        ranked_findings,
        decision,
        max_findings_per_iteration,
    );
    if filtered.is_empty() {
        SensitiveFilteringResult::AllSkipped
    } else {
        SensitiveFilteringResult::Proceed(filtered)
    }
}

fn sensitive_finding_counts(findings: &[ReviewFinding]) -> (usize, usize) {
    findings.iter().fold((0_usize, 0_usize), |acc, finding| {
        let flags = classify_sensitive_finding(finding);
        (
            acc.0 + usize::from(flags.security_auth),
            acc.1 + usize::from(flags.behavior_change),
        )
    })
}

async fn prompt_for_sensitive_findings(
    sess: Arc<Session>,
    ctx: Arc<TurnContext>,
    iteration: u8,
    security_auth_count: usize,
    behavior_change_count: usize,
) -> SensitiveFindingsDecision {
    let mut category_notes = Vec::new();
    if security_auth_count > 0 {
        category_notes.push(format!("{security_auth_count} security/auth"));
    }
    if behavior_change_count > 0 {
        category_notes.push(format!("{behavior_change_count} behavior-changing"));
    }
    let categories = category_notes.join(" + ");

    let args = RequestUserInputArgs {
        questions: vec![RequestUserInputQuestion {
            id: SENSITIVE_FINDINGS_QUESTION_ID.to_string(),
            header: "Sensitive findings detected".to_string(),
            question: format!(
                "Iteration {iteration} includes {categories} findings. How should auto-review proceed?"
            ),
            is_other: false,
            is_secret: false,
            options: Some(vec![
                RequestUserInputQuestionOption {
                    label: SENSITIVE_FINDINGS_OPTION_APPLY_ALL.to_string(),
                    description: "Apply all selected findings for this iteration.".to_string(),
                },
                RequestUserInputQuestionOption {
                    label: SENSITIVE_FINDINGS_OPTION_SKIP_SECURITY.to_string(),
                    description: "Skip security/auth findings this iteration, apply the rest."
                        .to_string(),
                },
                RequestUserInputQuestionOption {
                    label: SENSITIVE_FINDINGS_OPTION_SKIP_BEHAVIOR.to_string(),
                    description: "Skip behavior-changing findings this iteration, apply the rest."
                        .to_string(),
                },
                RequestUserInputQuestionOption {
                    label: SENSITIVE_FINDINGS_OPTION_SKIP_BOTH.to_string(),
                    description:
                        "Skip both security/auth and behavior-changing findings this iteration."
                            .to_string(),
                },
                RequestUserInputQuestionOption {
                    label: SENSITIVE_FINDINGS_OPTION_CANCEL.to_string(),
                    description: "Stop auto-review immediately.".to_string(),
                },
            ]),
        }],
    };
    let call_id = format!("auto-review-sensitive-findings-{iteration}");
    let response = sess.request_user_input(&ctx, call_id, args).await;
    parse_sensitive_findings_decision(response)
}

fn parse_sensitive_findings_decision(
    response: Option<RequestUserInputResponse>,
) -> SensitiveFindingsDecision {
    let Some(response) = response else {
        return SensitiveFindingsDecision::Cancel;
    };
    let Some(answer) = response.answers.get(SENSITIVE_FINDINGS_QUESTION_ID) else {
        return SensitiveFindingsDecision::Cancel;
    };
    if answer
        .answers
        .iter()
        .any(|choice| choice == SENSITIVE_FINDINGS_OPTION_APPLY_ALL)
    {
        SensitiveFindingsDecision::ApplyAll
    } else if answer
        .answers
        .iter()
        .any(|choice| choice == SENSITIVE_FINDINGS_OPTION_SKIP_SECURITY)
    {
        SensitiveFindingsDecision::SkipSecurity
    } else if answer
        .answers
        .iter()
        .any(|choice| choice == SENSITIVE_FINDINGS_OPTION_SKIP_BEHAVIOR)
    {
        SensitiveFindingsDecision::SkipBehavior
    } else if answer
        .answers
        .iter()
        .any(|choice| choice == SENSITIVE_FINDINGS_OPTION_SKIP_BOTH)
    {
        SensitiveFindingsDecision::SkipBoth
    } else {
        SensitiveFindingsDecision::Cancel
    }
}

fn filter_findings_by_decision(
    findings: &[ReviewFinding],
    decision: SensitiveFindingsDecision,
) -> Vec<ReviewFinding> {
    findings
        .iter()
        .filter(|&finding| {
            let flags = classify_sensitive_finding(finding);
            match decision {
                SensitiveFindingsDecision::ApplyAll => true,
                SensitiveFindingsDecision::SkipSecurity => !flags.security_auth,
                SensitiveFindingsDecision::SkipBehavior => !flags.behavior_change,
                SensitiveFindingsDecision::SkipBoth => {
                    !flags.security_auth && !flags.behavior_change
                }
                SensitiveFindingsDecision::Cancel => false,
            }
        })
        .cloned()
        .collect()
}

fn findings_for_iteration_after_decision(
    ranked_findings: &[ReviewFinding],
    decision: SensitiveFindingsDecision,
    max_findings_per_iteration: usize,
) -> Vec<ReviewFinding> {
    if decision == SensitiveFindingsDecision::ApplyAll {
        return take_top_findings(ranked_findings, max_findings_per_iteration);
    }

    let mut filtered = filter_findings_by_decision(ranked_findings, decision);
    filtered.truncate(max_findings_per_iteration);
    filtered
}

fn classify_sensitive_finding(finding: &ReviewFinding) -> SensitiveFindingFlags {
    let text = format!("{} {}", finding.title, finding.body).to_lowercase();
    SensitiveFindingFlags {
        security_auth: contains_any_keyword(&text, SECURITY_AUTH_KEYWORDS),
        behavior_change: contains_any_keyword(&text, BEHAVIOR_CHANGE_KEYWORDS),
    }
}

fn contains_any_keyword(text: &str, keywords: &[&str]) -> bool {
    keywords
        .iter()
        .any(|keyword| contains_keyword_on_word_boundaries(text, keyword))
}

fn contains_keyword_on_word_boundaries(text: &str, keyword: &str) -> bool {
    if keyword.is_empty() {
        return false;
    }

    let mut offset = 0;
    while let Some(relative_start) = text[offset..].find(keyword) {
        let start = offset + relative_start;
        let end = start + keyword.len();
        let left_boundary = text[..start]
            .chars()
            .next_back()
            .is_none_or(|ch| !is_keyword_char(ch));
        let right_boundary = text[end..]
            .chars()
            .next()
            .is_none_or(|ch| !is_keyword_char(ch));
        if left_boundary && right_boundary {
            return true;
        }
        offset = start + 1;
    }
    false
}

fn is_keyword_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn build_fix_prompt(
    iteration: u8,
    max_iterations: u8,
    findings: &[ReviewFinding],
    validation_commands: &[String],
    auto_fix_prompt: Option<&str>,
    parallel_tool_calls: bool,
    scope_groups: &[FixScopeGroup],
) -> String {
    let findings_block = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            format!(
                "{i}. {title}\n   - {body}\n   - {path}:{start}",
                i = index + 1,
                title = finding.title,
                body = finding.body,
                path = finding.code_location.absolute_file_path.display(),
                start = finding.code_location.line_range.start
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let execution_footer = build_execution_footer(
        findings_block.as_str(),
        validation_commands,
        parallel_tool_calls,
        scope_groups,
    );

    if let Some(prompt) = auto_fix_prompt {
        return format!("{prompt}\n\n{execution_footer}");
    }

    format!(
        "You are running auto-review iteration {iteration} of {max_iterations}.\n\
Apply the smallest safe edits that address ONLY the findings below.\n\
Do not perform unrelated refactors.\n\
Treat finding file paths as the primary scope for edits and investigation.\n\
Before editing, run only lightweight scope checks when needed (for example `git diff --name-only` or `git diff --stat`).\n\
When inspecting context, prefer path-scoped commands (for example `git diff -- <path>`) and avoid large unscoped diff dumps.\n\
Do not rerun expensive commands if equivalent output from this iteration is already available.\n\
\n\n\
{execution_footer}"
    )
}

fn build_execution_footer(
    findings_block: &str,
    validation_commands: &[String],
    parallel_tool_calls: bool,
    scope_groups: &[FixScopeGroup],
) -> String {
    let validation_block = validation_commands
        .iter()
        .map(|command| format!("- {command}"))
        .collect::<Vec<_>>()
        .join("\n");
    let parallel_mode = if parallel_tool_calls {
        "parallel grouped diffs are allowed"
    } else {
        "parallel grouped diffs are unavailable; keep grouped order and run serially"
    };
    let groups_block = render_scope_groups(scope_groups);
    format!(
        "Execution constraints (mandatory):\n\
- Use finding-led grouped scope inspection to keep feature-related files cohesive.\n\
- Group fanout cap: {MAX_SCOPE_GROUP_FANOUT}; files per group cap: {MAX_FILES_PER_SCOPE_GROUP}.\n\
- Soft shell-command budget for this turn: {SOFT_SHELL_COMMAND_BUDGET} commands.\n\
- If scoped evidence is still insufficient, allow at most {MAX_BROADEN_FALLBACK_COMMANDS} broader follow-up command.\n\
- {parallel_mode}.\n\
- If a file is untracked and not present in path-scoped diff output, read the file directly instead of retrying the same diff command.\n\
\n\
Scope groups (finding-led, module-cohesive):\n\
{groups_block}\n\
\n\
Findings:\n\
{findings_block}\n\
\n\
After edits, run these validation commands and fix any failures before ending your turn:\n\
{validation_block}"
    )
}

fn build_fix_scope_groups(findings: &[ReviewFinding]) -> Vec<FixScopeGroup> {
    if findings.is_empty() {
        return Vec::new();
    }

    let mut grouped: HashMap<String, FixScopeGroup> = HashMap::new();
    let mut insertion_order: Vec<String> = Vec::new();
    for (index, finding) in findings.iter().enumerate() {
        let file_path = finding
            .code_location
            .absolute_file_path
            .display()
            .to_string();
        let module = module_key_for_path(finding.code_location.absolute_file_path.as_path());
        let entry = grouped.entry(module.clone()).or_insert_with(|| {
            insertion_order.push(module.clone());
            FixScopeGroup {
                module: module.clone(),
                finding_indices: Vec::new(),
                files: Vec::new(),
            }
        });
        if !entry.finding_indices.contains(&(index + 1)) {
            entry.finding_indices.push(index + 1);
        }
        if !entry.files.contains(&file_path) {
            entry.files.push(file_path);
        }
    }

    let mut result: Vec<FixScopeGroup> = Vec::new();
    for module in insertion_order {
        let Some(group) = grouped.remove(&module) else {
            continue;
        };
        for chunk in group.files.chunks(MAX_FILES_PER_SCOPE_GROUP) {
            if result.len() >= MAX_SCOPE_GROUP_FANOUT {
                break;
            }
            result.push(FixScopeGroup {
                module: group.module.clone(),
                finding_indices: group.finding_indices.clone(),
                files: chunk.to_vec(),
            });
        }
        if result.len() >= MAX_SCOPE_GROUP_FANOUT {
            break;
        }
    }
    result
}

fn module_key_for_path(path: &Path) -> String {
    match path.parent() {
        Some(parent) => parent.display().to_string(),
        None => path.display().to_string(),
    }
}

fn render_scope_groups(scope_groups: &[FixScopeGroup]) -> String {
    if scope_groups.is_empty() {
        return "- (none; inspect finding file paths directly)".to_string();
    }
    scope_groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            let findings = group
                .finding_indices
                .iter()
                .map(|finding_index| format!("#{finding_index}"))
                .collect::<Vec<_>>()
                .join(", ");
            let files = group
                .files
                .iter()
                .map(|file| format!("`{file}`"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "- G{group_id} module `{module}` (findings: {findings}) -> {files}",
                group_id = index + 1,
                module = group.module.as_str()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn findings_signature(output: &ReviewOutputEvent) -> String {
    let mut entries = output
        .findings
        .iter()
        .map(|finding| {
            format!(
                "{}|{}:{}-{}",
                finding.title,
                finding.code_location.absolute_file_path.display(),
                finding.code_location.line_range.start,
                finding.code_location.line_range.end
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::protocol::ReviewCodeLocation;
    use codex_protocol::protocol::ReviewLineRange;
    use codex_protocol::request_user_input::RequestUserInputAnswer;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn finding(title: &str, priority: i32, confidence: f32, line: u32) -> ReviewFinding {
        ReviewFinding {
            title: title.to_string(),
            body: "body".to_string(),
            confidence_score: confidence,
            priority,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/file.rs"),
                line_range: ReviewLineRange {
                    start: line,
                    end: line,
                },
            },
        }
    }

    #[test]
    fn collects_default_validation_command() {
        let commands = collect_validation_commands(Vec::new());
        assert_eq!(commands, vec![BASE_VALIDATION_COMMAND.to_string()]);
    }

    #[test]
    fn uses_cached_check_without_default_unstaged_validation() {
        let commands = collect_validation_commands(vec!["git diff --cached --check".to_string()]);
        assert_eq!(commands, vec!["git diff --cached --check".to_string()]);
    }

    #[test]
    fn select_findings_prefers_priority_then_confidence() {
        let findings = vec![
            finding("low-priority", 3, 1.0, 10),
            finding("higher-confidence", 1, 0.9, 12),
            finding("lower-confidence", 1, 0.4, 13),
        ];
        let ranked = sort_findings(&findings);
        let selected = take_top_findings(&ranked, 2);
        let titles = selected
            .iter()
            .map(|item| item.title.as_str())
            .collect::<Vec<_>>();
        assert_eq!(titles, vec!["higher-confidence", "lower-confidence"]);
    }

    #[test]
    fn uses_uncommitted_target_after_first_iteration() {
        let initial = ReviewTarget::BaseBranch {
            branch: "main".to_string(),
        };
        let first = iteration_target(&initial, 1);
        let second = iteration_target(&initial, 2);
        assert_eq!(first, initial);
        assert_eq!(second, initial);
    }

    #[test]
    fn commit_target_switches_to_uncommitted_after_first_iteration() {
        let initial = ReviewTarget::Commit {
            sha: "1234567".to_string(),
            title: Some("test commit".to_string()),
        };
        let first = iteration_target(&initial, 1);
        let second = iteration_target(&initial, 2);
        assert_eq!(first, initial);
        assert_eq!(second, ReviewTarget::UncommittedChanges);
    }

    #[test]
    fn staged_target_switches_to_uncommitted_after_first_iteration() {
        let staged = ReviewTarget::Custom {
            instructions: AUTO_REVIEW_STAGED_PROMPT.to_string(),
        };
        let first = iteration_target(&staged, 1);
        let second = iteration_target(&staged, 2);
        assert_eq!(first, staged);
        assert_eq!(second, ReviewTarget::UncommittedChanges);
    }

    #[test]
    fn parses_sensitive_decision_from_response() {
        let mut answers = HashMap::new();
        answers.insert(
            SENSITIVE_FINDINGS_QUESTION_ID.to_string(),
            RequestUserInputAnswer {
                answers: vec![SENSITIVE_FINDINGS_OPTION_SKIP_SECURITY.to_string()],
            },
        );
        let response = RequestUserInputResponse { answers };
        let decision = parse_sensitive_findings_decision(Some(response));
        assert_eq!(decision, SensitiveFindingsDecision::SkipSecurity);
    }

    #[test]
    fn classifies_security_and_behavior_findings() {
        let security = ReviewFinding {
            title: "[P1] Add authentication checks".to_string(),
            body: "Missing token validation permits unauthorized access.".to_string(),
            confidence_score: 0.9,
            priority: 1,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/auth.rs"),
                line_range: ReviewLineRange { start: 20, end: 20 },
            },
        };
        let behavior = ReviewFinding {
            title: "[P2] Prevent breaking behavior change".to_string(),
            body: "This is an incompatible API change without migration.".to_string(),
            confidence_score: 0.8,
            priority: 2,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/api.rs"),
                line_range: ReviewLineRange { start: 22, end: 22 },
            },
        };
        let security_flags = classify_sensitive_finding(&security);
        let behavior_flags = classify_sensitive_finding(&behavior);
        assert_eq!(
            security_flags,
            SensitiveFindingFlags {
                security_auth: true,
                behavior_change: false,
            }
        );
        assert_eq!(
            behavior_flags,
            SensitiveFindingFlags {
                security_auth: false,
                behavior_change: true,
            }
        );
    }

    #[test]
    fn classifier_avoids_substring_false_positives() {
        let benign = ReviewFinding {
            title: "Improve author docs".to_string(),
            body: "Tokenizer updates for dependency injection ergonomics.".to_string(),
            confidence_score: 0.8,
            priority: 2,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/docs.rs"),
                line_range: ReviewLineRange { start: 10, end: 10 },
            },
        };
        let flags = classify_sensitive_finding(&benign);
        assert_eq!(
            flags,
            SensitiveFindingFlags {
                security_auth: false,
                behavior_change: false,
            }
        );
    }

    #[test]
    fn classifier_still_matches_precise_security_terms() {
        let finding = ReviewFinding {
            title: "Prevent sql injection".to_string(),
            body: "Bearer token verification is missing.".to_string(),
            confidence_score: 0.9,
            priority: 1,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/security.rs"),
                line_range: ReviewLineRange { start: 12, end: 12 },
            },
        };
        let flags = classify_sensitive_finding(&finding);
        assert_eq!(
            flags,
            SensitiveFindingFlags {
                security_auth: true,
                behavior_change: false,
            }
        );
    }

    #[test]
    fn filters_findings_by_sensitive_decision() {
        let security = ReviewFinding {
            title: "Authentication bypass".to_string(),
            body: "Missing auth token check".to_string(),
            confidence_score: 0.9,
            priority: 1,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/security.rs"),
                line_range: ReviewLineRange { start: 1, end: 1 },
            },
        };
        let behavior = ReviewFinding {
            title: "Breaking API behavior".to_string(),
            body: "This introduces a behavior change".to_string(),
            confidence_score: 0.8,
            priority: 2,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/behavior.rs"),
                line_range: ReviewLineRange { start: 2, end: 2 },
            },
        };
        let neutral = ReviewFinding {
            title: "Rename local variable".to_string(),
            body: "Improve readability".to_string(),
            confidence_score: 0.7,
            priority: 3,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/neutral.rs"),
                line_range: ReviewLineRange { start: 3, end: 3 },
            },
        };

        let filtered = filter_findings_by_decision(
            &[security, behavior, neutral.clone()],
            SensitiveFindingsDecision::SkipBoth,
        );
        assert_eq!(filtered, vec![neutral]);
    }

    #[test]
    fn builds_default_fix_prompt() {
        let findings = vec![finding("Bug", 1, 0.9, 12)];
        let scope_groups = build_fix_scope_groups(&findings);
        let prompt = build_fix_prompt(
            1,
            3,
            &findings,
            &[BASE_VALIDATION_COMMAND.to_string()],
            None,
            true,
            &scope_groups,
        );
        assert!(prompt.contains("You are running auto-review iteration 1 of 3."));
        assert!(prompt.contains("Execution constraints (mandatory):"));
        assert!(prompt.contains("Scope groups (finding-led, module-cohesive):"));
        assert!(prompt.contains("G1 module `/tmp`"));
        assert!(prompt.contains(&format!("- {BASE_VALIDATION_COMMAND}")));
    }

    #[test]
    fn builds_custom_fix_prompt_from_config() {
        let findings = vec![finding("Bug", 1, 0.9, 12)];
        let scope_groups = build_fix_scope_groups(&findings);
        let prompt = build_fix_prompt(
            1,
            3,
            &findings,
            &[BASE_VALIDATION_COMMAND.to_string()],
            Some("Use exactly this fix prompt."),
            false,
            &scope_groups,
        );
        assert!(prompt.starts_with("Use exactly this fix prompt."));
        assert!(prompt.contains("Execution constraints (mandatory):"));
        assert!(prompt.contains("parallel grouped diffs are unavailable"));
    }

    #[test]
    fn fix_scope_groups_follow_finding_order_and_cap_fanout() {
        let findings = (0..20)
            .map(|idx| ReviewFinding {
                title: format!("Bug {idx}"),
                body: "body".to_string(),
                confidence_score: 0.9,
                priority: 1,
                code_location: ReviewCodeLocation {
                    absolute_file_path: PathBuf::from(format!("/repo/module-{idx}/file-{idx}.rs")),
                    line_range: ReviewLineRange {
                        start: (idx + 1) as u32,
                        end: (idx + 1) as u32,
                    },
                },
            })
            .collect::<Vec<_>>();
        let groups = build_fix_scope_groups(&findings);
        assert_eq!(groups.len(), MAX_SCOPE_GROUP_FANOUT);
        assert_eq!(groups[0].module, "/repo/module-0");
    }

    #[test]
    fn sensitive_skip_backfills_with_non_sensitive_findings() {
        let sensitive = ReviewFinding {
            title: "Missing authentication".to_string(),
            body: "auth token validation is missing".to_string(),
            confidence_score: 0.9,
            priority: 1,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/sensitive.rs"),
                line_range: ReviewLineRange { start: 1, end: 1 },
            },
        };
        let neutral = ReviewFinding {
            title: "Rename variable".to_string(),
            body: "Improve readability".to_string(),
            confidence_score: 0.8,
            priority: 2,
            code_location: ReviewCodeLocation {
                absolute_file_path: PathBuf::from("/tmp/neutral.rs"),
                line_range: ReviewLineRange { start: 2, end: 2 },
            },
        };
        let ranked = vec![sensitive, neutral.clone()];
        let selected = findings_for_iteration_after_decision(
            &ranked,
            SensitiveFindingsDecision::SkipSecurity,
            1,
        );
        assert_eq!(selected, vec![neutral]);
    }
}
