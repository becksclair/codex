use std::sync::Arc;

use async_trait::async_trait;
use codex_protocol::protocol::AutoReviewRequest;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ReviewFinding;
use codex_protocol::protocol::ReviewOutputEvent;
use codex_protocol::protocol::ReviewRequest;
use codex_protocol::protocol::ReviewTarget;
use codex_protocol::protocol::WarningEvent;
use codex_protocol::user_input::UserInput;
use tokio_util::sync::CancellationToken;

use crate::codex::TurnContext;
use crate::codex::run_turn;
use crate::review_prompts::resolve_review_request;
use crate::state::TaskKind;

use super::SessionTask;
use super::SessionTaskContext;
use super::review::exit_review_mode;
use super::review::run_review_delegate;

const DEFAULT_MAX_ITERATIONS: u8 = 10;
const DEFAULT_MAX_FINDINGS_PER_ITERATION: usize = 5;
const DEFAULT_STAGNATION_ROUNDS: u8 = 2;
const BASE_VALIDATION_COMMAND: &str = "git diff --check";

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
            .max(1);
        let max_findings_per_iteration = self
            .request
            .max_findings_per_iteration
            .map(usize::from)
            .unwrap_or(DEFAULT_MAX_FINDINGS_PER_ITERATION)
            .max(1);
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

            let selected_findings =
                select_findings(&review_output.findings, max_findings_per_iteration);
            let fix_prompt = build_fix_prompt(
                iteration,
                max_iterations,
                &selected_findings,
                &validation_commands,
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
        initial.clone()
    } else {
        ReviewTarget::UncommittedChanges
    }
}

fn collect_validation_commands(user_commands: Vec<String>) -> Vec<String> {
    let mut commands = vec![BASE_VALIDATION_COMMAND.to_string()];
    commands.extend(
        user_commands
            .into_iter()
            .map(|command| command.trim().to_string())
            .filter(|command| !command.is_empty()),
    );
    commands
}

fn select_findings(findings: &[ReviewFinding], max_findings: usize) -> Vec<ReviewFinding> {
    let mut selected = findings.to_vec();
    selected.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| right.confidence_score.total_cmp(&left.confidence_score))
    });
    selected.truncate(max_findings);
    selected
}

fn build_fix_prompt(
    iteration: u8,
    max_iterations: u8,
    findings: &[ReviewFinding],
    validation_commands: &[String],
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

    let validation_block = validation_commands
        .iter()
        .map(|command| format!("- {command}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "You are running auto-review iteration {iteration} of {max_iterations}.\n\
Apply the smallest safe edits that address ONLY the findings below.\n\
Do not perform unrelated refactors.\n\
\n\
Findings:\n\
{findings_block}\n\
\n\
After edits, run these validation commands and fix any failures before ending your turn:\n\
{validation_block}"
    )
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
    use pretty_assertions::assert_eq;
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
    fn select_findings_prefers_priority_then_confidence() {
        let findings = vec![
            finding("low-priority", 3, 1.0, 10),
            finding("higher-confidence", 1, 0.9, 12),
            finding("lower-confidence", 1, 0.4, 13),
        ];
        let selected = select_findings(&findings, 2);
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
        assert_eq!(second, ReviewTarget::UncommittedChanges);
    }
}
