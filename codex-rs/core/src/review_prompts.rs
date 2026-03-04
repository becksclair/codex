use codex_git::merge_base_with_head;
use codex_protocol::protocol::ReviewRequest;
use codex_protocol::protocol::ReviewTarget;
use std::path::Path;

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedReviewRequest {
    pub target: ReviewTarget,
    pub prompt: String,
    pub user_facing_hint: String,
}

const UNCOMMITTED_PROMPT: &str = "Review the current code changes (staged, unstaged, and untracked files) and provide prioritized findings. Start with `git diff --name-only` and `git diff --stat` to map scope, then inspect likely-risk files with path-scoped `git diff -- <path>`. Avoid large unscoped diff dumps unless targeted checks are insufficient.";

const BASE_BRANCH_PROMPT_BACKUP: &str = "Review the code changes against the base branch '{branch}'. Start by finding the merge diff between the current branch and {branch}'s upstream e.g. (`git merge-base HEAD \"$(git rev-parse --abbrev-ref \"{branch}@{upstream}\")\"`). First run `git diff --name-only <mergeBaseSha>` and `git diff --stat <mergeBaseSha>` to map scope, then inspect likely-risk files with `git diff <mergeBaseSha> -- <path>`. Avoid large unscoped diff dumps unless targeted checks are insufficient. Provide prioritized, actionable findings.";
const BASE_BRANCH_PROMPT: &str = "Review the code changes against the base branch '{baseBranch}'. The merge base commit for this comparison is {mergeBaseSha}. First run `git diff --name-only {mergeBaseSha}` and `git diff --stat {mergeBaseSha}` to map scope, then inspect likely-risk files with `git diff {mergeBaseSha} -- <path>`. Avoid large unscoped diff dumps unless targeted checks are insufficient. Provide prioritized, actionable findings.";

const COMMIT_PROMPT_WITH_TITLE: &str = "Review the code changes introduced by commit {sha} (\"{title}\"). Start with `git show --name-only --stat --format= {sha}`, then inspect likely-risk files with `git show {sha} -- <path>`. Avoid large unscoped output dumps unless targeted checks are insufficient. Provide prioritized, actionable findings.";
const COMMIT_PROMPT: &str = "Review the code changes introduced by commit {sha}. Start with `git show --name-only --stat --format= {sha}`, then inspect likely-risk files with `git show {sha} -- <path>`. Avoid large unscoped output dumps unless targeted checks are insufficient. Provide prioritized, actionable findings.";

pub const AUTO_REVIEW_STAGED_PROMPT: &str = "Review the code changes currently staged in git (index only). Start with `git diff --cached --name-only` and `git diff --cached --stat`, then inspect likely-risk files with `git diff --cached -- <path>`. Avoid large unscoped diff dumps unless targeted checks are insufficient. Provide prioritized, actionable findings.";
pub const AUTO_REVIEW_ALL_PROJECT_PROMPT: &str = "Review the project as a whole (not only pending diffs) and provide prioritized, actionable findings with concrete file references. This is full-project mode: findings may reference files outside pending diff overlap constraints. Start with lightweight scope discovery and then inspect the highest-risk files first with scoped commands.";

const EXECUTION_ADDENDUM: &str = "\
\n\nExecution strategy (required):\
\n- Run one lightweight manifest pass first, then only conditional extras when needed; do not run redundant scope commands.\
\n- Group related files by module/path cohesion and inspect grouped diffs before falling back to file-by-file probing.\
\n- Favor finding-led inspection order: highest-priority/highest-confidence candidates first.\
\n- Use bounded fanout for grouped diff inspection (max 6 groups, max 10 files/group).\
\n- Keep probing within a soft budget of 16 shell commands for this turn; allow only one broadened follow-up command when scoped evidence is insufficient.\
\n- If parallel tool calls are supported, run group inspections in parallel; otherwise keep the same group order and run serially.\
\n- For staged-only scopes, do not run unstaged probes until staged evidence is exhausted.\
\n- For untracked files that do not appear in path-scoped git diff output, read the file content directly instead of retrying the same diff command.";

pub fn resolve_review_request(
    request: ReviewRequest,
    cwd: &Path,
) -> anyhow::Result<ResolvedReviewRequest> {
    let target = request.target;
    let prompt = review_prompt(&target, cwd)?;
    let user_facing_hint = request
        .user_facing_hint
        .unwrap_or_else(|| user_facing_hint(&target));

    Ok(ResolvedReviewRequest {
        target,
        prompt,
        user_facing_hint,
    })
}

pub fn review_prompt(target: &ReviewTarget, cwd: &Path) -> anyhow::Result<String> {
    let (prompt, add_execution_addendum) = match target {
        ReviewTarget::UncommittedChanges => (UNCOMMITTED_PROMPT.to_string(), true),
        ReviewTarget::BaseBranch { branch } => {
            if let Some(commit) = merge_base_with_head(cwd, branch)? {
                (
                    BASE_BRANCH_PROMPT
                        .replace("{baseBranch}", branch)
                        .replace("{mergeBaseSha}", &commit),
                    true,
                )
            } else {
                (BASE_BRANCH_PROMPT_BACKUP.replace("{branch}", branch), true)
            }
        }
        ReviewTarget::Commit { sha, title } => {
            if let Some(title) = title {
                (
                    COMMIT_PROMPT_WITH_TITLE
                        .replace("{sha}", sha)
                        .replace("{title}", title),
                    true,
                )
            } else {
                (COMMIT_PROMPT.replace("{sha}", sha), true)
            }
        }
        ReviewTarget::Custom { instructions } => {
            let prompt = instructions.trim();
            if prompt.is_empty() {
                anyhow::bail!("Review prompt cannot be empty");
            }
            if prompt == AUTO_REVIEW_ALL_PROJECT_PROMPT {
                (prompt.to_string(), false)
            } else {
                (prompt.to_string(), true)
            }
        }
    };

    if add_execution_addendum {
        Ok(format!("{prompt}{EXECUTION_ADDENDUM}"))
    } else {
        Ok(prompt)
    }
}

pub fn user_facing_hint(target: &ReviewTarget) -> String {
    match target {
        ReviewTarget::UncommittedChanges => "current changes".to_string(),
        ReviewTarget::BaseBranch { branch } => format!("changes against '{branch}'"),
        ReviewTarget::Commit { sha, title } => {
            let short_sha: String = sha.chars().take(7).collect();
            if let Some(title) = title {
                format!("commit {short_sha}: {title}")
            } else {
                format!("commit {short_sha}")
            }
        }
        ReviewTarget::Custom { instructions } => instructions.trim().to_string(),
    }
}

impl From<ResolvedReviewRequest> for ReviewRequest {
    fn from(resolved: ResolvedReviewRequest) -> Self {
        ReviewRequest {
            target: resolved.target,
            user_facing_hint: Some(resolved.user_facing_hint),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn custom_review_prompt_is_trimmed() {
        let target = ReviewTarget::Custom {
            instructions: "  check this please  ".to_string(),
        };
        let prompt = review_prompt(&target, Path::new(".")).expect("custom review prompt");
        assert!(prompt.starts_with("check this please"));
        assert!(prompt.contains("Execution strategy (required):"));
    }

    #[test]
    fn custom_review_prompt_rejects_empty_values() {
        let target = ReviewTarget::Custom {
            instructions: "   ".to_string(),
        };
        let err = review_prompt(&target, Path::new(".")).expect_err("empty custom prompt");
        assert_eq!(err.to_string(), "Review prompt cannot be empty");
    }

    #[test]
    fn diff_scoped_prompts_include_lightweight_scope_guidance() {
        let uncommitted = review_prompt(&ReviewTarget::UncommittedChanges, Path::new("."))
            .expect("uncommitted prompt");
        assert!(uncommitted.contains("git diff --name-only"));
        assert!(uncommitted.contains("git diff -- <path>"));
        assert!(uncommitted.contains("soft budget of 16"));

        let commit = review_prompt(
            &ReviewTarget::Commit {
                sha: "abcdef".to_string(),
                title: None,
            },
            Path::new("."),
        )
        .expect("commit prompt");
        assert!(commit.contains("git show --name-only --stat --format= abcdef"));
        assert!(commit.contains("untracked files"));

        let staged = review_prompt(
            &ReviewTarget::Custom {
                instructions: AUTO_REVIEW_STAGED_PROMPT.to_string(),
            },
            Path::new("."),
        )
        .expect("staged prompt");
        assert!(staged.contains("git diff --cached --name-only"));
        assert!(staged.contains("do not run unstaged probes"));
    }

    #[test]
    fn all_project_prompt_contains_exception_language() {
        assert!(AUTO_REVIEW_ALL_PROJECT_PROMPT.contains("full-project mode"));
        assert!(AUTO_REVIEW_ALL_PROJECT_PROMPT.contains("outside pending diff overlap"));
        let prompt = review_prompt(
            &ReviewTarget::Custom {
                instructions: AUTO_REVIEW_ALL_PROJECT_PROMPT.to_string(),
            },
            Path::new("."),
        )
        .expect("all project prompt");
        assert_eq!(prompt, AUTO_REVIEW_ALL_PROJECT_PROMPT);
    }
}
