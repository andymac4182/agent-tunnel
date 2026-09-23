use crate::error::{HarnessError, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};

const FORCED_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const OUTPUT_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const OUTPUT_ABORT_JOIN_TIMEOUT: Duration = Duration::from_millis(100);

/// A process command used by a real-socket smoke test.
#[derive(Clone, Debug)]
pub struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub current_dir: Option<PathBuf>,
}

impl ProcessSpec {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            current_dir: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn current_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(path.into());
        self
    }
}

/// A child process with bounded diagnostic capture and explicit shutdown.
pub struct ManagedProcess {
    name: String,
    pid: Option<u32>,
    child: Child,
    output_dir: TempDir,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stdout_overflow: Arc<AtomicBool>,
    stderr_overflow: Arc<AtomicBool>,
    stdout_read_error: Arc<AtomicBool>,
    stderr_read_error: Arc<AtomicBool>,
    stdout_task: Option<JoinHandle<()>>,
    stderr_task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ManagedProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedProcess")
            .field("name", &self.name)
            .field("pid", &self.child.id())
            .field("output_dir", &self.output_dir.path())
            .finish()
    }
}

impl ManagedProcess {
    pub async fn spawn(name: impl Into<String>, spec: ProcessSpec) -> Result<Self> {
        let name = name.into();
        let output_dir = tempfile::tempdir()?;
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .envs(spec.env.iter().map(|(key, value)| (key, value)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // A cancellation of the async shutdown path must still terminate the
        // owned CLI.  The explicit shutdown path below remains responsible
        // for bounded reaping; this is the destructor fallback only.
        command.kill_on_drop(true);
        if let Some(current_dir) = spec.current_dir {
            command.current_dir(current_dir);
        }
        let mut child = command.spawn().map_err(|error| {
            HarnessError::Process(format!(
                "starting {name} ({}): {error}",
                spec.program.display()
            ))
        })?;
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let stdout_overflow = Arc::new(AtomicBool::new(false));
        let stderr_overflow = Arc::new(AtomicBool::new(false));
        let stdout_read_error = Arc::new(AtomicBool::new(false));
        let stderr_read_error = Arc::new(AtomicBool::new(false));
        let stdout_task = spawn_drain(
            child.stdout.take(),
            Arc::clone(&stdout),
            Arc::clone(&stdout_overflow),
            Arc::clone(&stdout_read_error),
        );
        let stderr_task = spawn_drain(
            child.stderr.take(),
            Arc::clone(&stderr),
            Arc::clone(&stderr_overflow),
            Arc::clone(&stderr_read_error),
        );
        Ok(Self {
            name,
            pid: child.id(),
            child,
            output_dir,
            stdout,
            stderr,
            stdout_overflow,
            stderr_overflow,
            stdout_read_error,
            stderr_read_error,
            stdout_task,
            stderr_task,
        })
    }

    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn output_dir(&self) -> &std::path::Path {
        self.output_dir.path()
    }

    pub fn stdout(&self) -> Vec<u8> {
        self.stdout
            .lock()
            .map(|output| output.clone())
            .unwrap_or_default()
    }

    pub fn stderr(&self) -> Vec<u8> {
        self.stderr
            .lock()
            .map(|output| output.clone())
            .unwrap_or_default()
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child
            .try_wait()
            .map_err(|error| HarnessError::Process(format!("checking {}: {error}", self.name)))
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        self.child
            .wait()
            .await
            .map_err(|error| HarnessError::Process(format!("waiting for {}: {error}", self.name)))
    }

    /// Request the process's normal shutdown path.  The CLI and the relay
    /// handle SIGINT and SIGTERM through one orderly stop path (M6-C23);
    /// generic fixtures still use [`Self::shutdown`] when a forced stop is
    /// the intended behavior.
    #[cfg(unix)]
    pub async fn request_stop(&mut self) -> Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        let Some(pid) = self.child.id() else {
            return Err(HarnessError::Process(format!(
                "requesting graceful stop for {} after it exited",
                self.name
            )));
        };
        let mut signal = Command::new("kill");
        signal.kill_on_drop(true).arg("-INT").arg(pid.to_string());
        let status = timeout(FORCED_REAP_TIMEOUT, signal.status())
            .await
            .map_err(|_| {
                HarnessError::Timeout(format!(
                    "requesting graceful stop for {} exceeded its bound",
                    self.name
                ))
            })?
            .map_err(|error| {
                HarnessError::Process(format!(
                    "requesting graceful stop for {}: {error}",
                    self.name
                ))
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(HarnessError::Process(format!(
                "requesting graceful stop for {} returned {status}",
                self.name
            )))
        }
    }

    /// Graceful process interrupts are intentionally explicit on platforms
    /// without the Unix signal contract used by the CLI.
    #[cfg(not(unix))]
    pub async fn request_stop(&mut self) -> Result<()> {
        Err(HarnessError::Unsupported(
            "graceful managed-process stop requires a Unix SIGINT implementation".into(),
        ))
    }

    /// Stop a child and wait for reaping within bounded waits.  An unresolved
    /// child or output-drain join is returned as an error; `kill_on_drop` is
    /// the final cancellation fallback so a failed smoke test cannot leave a
    /// relay/client process running.
    pub async fn shutdown(mut self, grace: Duration) -> Result<std::process::ExitStatus> {
        let status = match self.try_wait() {
            Err(error) => Err(error),
            Ok(Some(_)) => self.wait().await,
            Ok(None) => match timeout(grace, self.child.wait()).await {
                Ok(result) => result.map_err(|error| {
                    HarnessError::Process(format!("waiting for {}: {error}", self.name))
                }),
                Err(_) => match self.child.start_kill() {
                    Err(error) => Err(HarnessError::Process(format!(
                        "stopping {}: {error}",
                        self.name
                    ))),
                    Ok(()) => match timeout(FORCED_REAP_TIMEOUT, self.child.wait()).await {
                        Ok(result) => result.map_err(|error| {
                            HarnessError::Process(format!("reaping {}: {error}", self.name))
                        }),
                        Err(_) => Err(HarnessError::Process(format!(
                            "reaping {} after kill exceeded {:?}",
                            self.name, FORCED_REAP_TIMEOUT
                        ))),
                    },
                },
            },
        };
        let output = self.join_output_tasks().await;
        let capture = crate::c11_capture::record_process_streams(
            self.pid,
            &self.name,
            &self.stdout(),
            &self.stderr(),
            self.stdout_overflow.load(Ordering::Acquire),
            self.stderr_overflow.load(Ordering::Acquire),
            self.stdout_read_error.load(Ordering::Acquire),
            self.stderr_read_error.load(Ordering::Acquire),
        );
        let result = match (status, output) {
            (Ok(status), Ok(())) => Ok(status),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(status_error), Err(output_error)) => Err(HarnessError::Process(format!(
                "{status_error}; {output_error}"
            ))),
        };
        match (result, capture) {
            (Ok(status), Ok(())) => Ok(status),
            (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
            (Err(result_error), Err(capture_error)) => Err(HarnessError::Process(format!(
                "{result_error}; {capture_error}"
            ))),
        }
    }

    async fn join_output_tasks(&mut self) -> Result<()> {
        let deadline = Instant::now() + OUTPUT_JOIN_TIMEOUT;
        let mut first_error = None;
        if let Err(error) = join_output_slot(&mut self.stdout_task, "stdout", deadline).await {
            first_error = Some(error);
        }
        if let Err(error) = join_output_slot(&mut self.stderr_task, "stderr", deadline).await {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
    }
}

async fn join_output_slot(
    slot: &mut Option<JoinHandle<()>>,
    stream: &'static str,
    deadline: Instant,
) -> Result<()> {
    let Some(mut task) = slot.take() else {
        return Ok(());
    };
    let result = match timeout_at(deadline, &mut task).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(HarnessError::Process(format!(
            "joining {stream} drain failed: {error}"
        ))),
        Err(_) => {
            task.abort();
            // The drain task only awaits the child's pipe and is cancellation
            // safe. Keep the handle owned while giving cancellation a final
            // bounded join opportunity; an unresolved handle is retained by
            // ManagedProcess so Drop can abort it again.
            match timeout(OUTPUT_ABORT_JOIN_TIMEOUT, &mut task).await {
                Ok(Ok(())) => Err(HarnessError::Process(format!(
                    "joining {stream} drain exceeded {:?}",
                    OUTPUT_JOIN_TIMEOUT
                ))),
                Ok(Err(error)) if error.is_cancelled() => Err(HarnessError::Process(format!(
                    "joining {stream} drain exceeded {:?} and was aborted",
                    OUTPUT_JOIN_TIMEOUT
                ))),
                Ok(Err(error)) => Err(HarnessError::Process(format!(
                    "joining {stream} drain failed after timeout: {error}"
                ))),
                Err(_) => Err(HarnessError::Process(format!(
                    "joining {stream} drain remained unresolved after {:?}",
                    OUTPUT_ABORT_JOIN_TIMEOUT
                ))),
            }
        }
    };
    if !task.is_finished() {
        *slot = Some(task);
    }
    result
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if self.child.id().is_some() {
            let _ = self.child.start_kill();
        }
        if let Some(task) = self.stdout_task.take() {
            task.abort();
        }
        if let Some(task) = self.stderr_task.take() {
            task.abort();
        }
    }
}

fn spawn_drain(
    reader: Option<impl tokio::io::AsyncRead + Unpin + Send + 'static>,
    output: Arc<Mutex<Vec<u8>>>,
    overflow: Arc<AtomicBool>,
    read_error: Arc<AtomicBool>,
) -> Option<JoinHandle<()>> {
    reader.map(|mut reader| {
        tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Err(_) => {
                        read_error.store(true, Ordering::Release);
                        break;
                    }
                    Ok(read) => {
                        if let Ok(mut output) = output.lock() {
                            // Keep diagnostics bounded even if a broken child
                            // floods stderr while the test is failing.
                            const MAX_CAPTURE: usize = 1024 * 1024;
                            let remaining = MAX_CAPTURE.saturating_sub(output.len());
                            let accepted = read.min(remaining);
                            output.extend_from_slice(&buffer[..accepted]);
                            if accepted != read {
                                // Keep draining after the exact bound. The
                                // first extra byte marks overflow while the
                                // remaining bytes are discarded, preventing a
                                // still-running child from blocking on a full pipe.
                                overflow.store(true, Ordering::Release);
                            }
                        } else {
                            read_error.store(true, Ordering::Release);
                        }
                    }
                }
            }
        })
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::{ManagedProcess, ProcessSpec};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn forced_shutdown_reaps_child_and_joins_output_drains() {
        let process = ManagedProcess::spawn(
            "bounded-shutdown-test",
            ProcessSpec::new("sh")
                .arg("-c")
                .arg("printf 'ready\\n'; exec sleep 10"),
        )
        .await
        .expect("spawn synthetic child");
        let started = Instant::now();
        let status = process
            .shutdown(Duration::from_millis(20))
            .await
            .expect("forced shutdown should reap synthetic child");

        assert!(!status.success());
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
