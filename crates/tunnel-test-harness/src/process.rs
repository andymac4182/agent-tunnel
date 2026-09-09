use crate::error::{HarnessError, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

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
    child: Child,
    output_dir: TempDir,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
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
        let stdout_task = spawn_drain(child.stdout.take(), Arc::clone(&stdout));
        let stderr_task = spawn_drain(child.stderr.take(), Arc::clone(&stderr));
        Ok(Self {
            name,
            child,
            output_dir,
            stdout,
            stderr,
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

    /// Stop a child and wait for reaping.  The process is always reaped so a
    /// failed smoke test cannot leave relay/client processes behind.
    pub async fn shutdown(mut self, grace: Duration) -> Result<std::process::ExitStatus> {
        let status = if self.try_wait()?.is_some() {
            self.wait().await
        } else {
            match tokio::time::timeout(grace, self.child.wait()).await {
                Ok(result) => result.map_err(|error| {
                    HarnessError::Process(format!("waiting for {}: {error}", self.name))
                }),
                Err(_) => {
                    self.child.kill().await.map_err(|error| {
                        HarnessError::Process(format!("stopping {}: {error}", self.name))
                    })?;
                    self.wait().await
                }
            }
        };
        self.join_output_tasks().await;
        status
    }

    async fn join_output_tasks(&mut self) {
        if let Some(task) = self.stdout_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.stderr_task.take() {
            let _ = task.await;
        }
    }
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
) -> Option<JoinHandle<()>> {
    reader.map(|mut reader| {
        tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if let Ok(mut output) = output.lock() {
                            // Keep diagnostics bounded even if a broken child
                            // floods stderr while the test is failing.
                            const MAX_CAPTURE: usize = 1024 * 1024;
                            let remaining = MAX_CAPTURE.saturating_sub(output.len());
                            output.extend_from_slice(&buffer[..read.min(remaining)]);
                            if output.len() == MAX_CAPTURE {
                                break;
                            }
                        }
                    }
                }
            }
        })
    })
}
