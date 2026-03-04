use async_trait::async_trait;
use codex_protocol::models::FunctionCallOutputBody;
use serde::Deserialize;
use serde::Serialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

use crate::function_tool::FunctionCallError;
use crate::protocol::EventMsg;
use crate::protocol::WarningEvent;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::handlers::parse_arguments;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;

pub(crate) const SPEAK_VOICE_MESSAGE_TOOL_NAME: &str = "speak_voice_message";
const SPEAK_BACKEND_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Default)]
pub struct SpeakVoiceMessageHandler;

#[derive(Debug, Deserialize)]
struct SpeakVoiceMessageArgs {
    message: String,
}

#[derive(Debug, Serialize)]
struct SpeakVoiceMessageResult {
    attempted: bool,
    delivered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[async_trait]
impl ToolHandler for SpeakVoiceMessageHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn is_mutating(&self, _invocation: &ToolInvocation) -> bool {
        true
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            payload,
            ..
        } = invocation;

        let arguments = match payload {
            ToolPayload::Function { arguments } => arguments,
            _ => {
                return Err(FunctionCallError::RespondToModel(
                    "speak_voice_message handler received unsupported payload".to_string(),
                ));
            }
        };

        let args: SpeakVoiceMessageArgs = parse_arguments(&arguments)?;
        let speak_argv = turn.config.speak.clone().ok_or_else(|| {
            FunctionCallError::RespondToModel("speak backend is not configured".to_string())
        })?;
        let Some((program, command_args)) = speak_argv.split_first() else {
            return Err(FunctionCallError::RespondToModel(
                "speak backend is not configured".to_string(),
            ));
        };
        if program.is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "speak backend command is empty".to_string(),
            ));
        }

        let delivery_error = match run_speak_backend(program, command_args, &args.message).await {
            Ok(()) => None,
            Err(error) => {
                let should_emit = session.mark_speak_failure_warning_emitted().await;
                if should_emit {
                    session
                        .send_event(
                            turn.as_ref(),
                            EventMsg::Warning(WarningEvent {
                                message: format!(
                                    "Voice playback failed while running \
`{SPEAK_VOICE_MESSAGE_TOOL_NAME}`: {error}. Further playback failures will be \
suppressed for this session."
                                ),
                            }),
                        )
                        .await;
                }
                Some(error)
            }
        };
        let delivered = delivery_error.is_none();

        let body = serde_json::to_string(&SpeakVoiceMessageResult {
            attempted: true,
            delivered,
            error: delivery_error,
        })
        .map_err(|err| {
            FunctionCallError::Fatal(format!(
                "failed to serialize speak_voice_message output: {err}"
            ))
        })?;

        Ok(ToolOutput::Function {
            body: FunctionCallOutputBody::Text(body),
            success: Some(delivered),
        })
    }
}

async fn run_speak_backend(
    program: &str,
    command_args: &[String],
    message: &str,
) -> Result<(), String> {
    let mut command = Command::new(program);
    command
        .kill_on_drop(true)
        .args(command_args)
        .arg(message)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to spawn speak backend command: {err}"))?;

    match tokio::time::timeout(SPEAK_BACKEND_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => {
            if status.success() {
                Ok(())
            } else {
                Err(format!("speak backend exited with status {status}"))
            }
        }
        Ok(Err(err)) => Err(format!(
            "failed while waiting for speak backend command: {err}"
        )),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(format!(
                "speak backend timed out after {} ms",
                SPEAK_BACKEND_TIMEOUT.as_millis()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn run_speak_backend_passes_message_as_final_argv_item() {
        let temp_dir = TempDir::new().expect("temp dir");
        let output_path = temp_dir.path().join("spoken.txt");
        let script = format!("printf '%s' \"$1\" > {}", output_path.display());
        let args = vec!["-lc".to_string(), script, "_".to_string()];

        run_speak_backend("sh", &args, "hello from codex")
            .await
            .expect("backend command should succeed");

        let text = std::fs::read_to_string(output_path).expect("read output");
        assert_eq!(text, "hello from codex");
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn run_speak_backend_reports_non_zero_exit_status() {
        let args = vec!["-lc".to_string(), "exit 7".to_string()];

        let err = run_speak_backend("sh", &args, "ignored")
            .await
            .expect_err("backend command should fail");

        assert!(err.contains("status"));
    }
}
