use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use osmanthus_guard::protocol::{RequestBody, ResponseBody, SessionDirection};
use osmanthus_guard::{OsmanthusError, Result};

const BUFFER_BYTES: usize = 4096;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("osmanthus-shell: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8> {
    let uid = unsafe { libc::getuid() };
    let policy = osmanthus_guard::system_policy::load()?
        .ok_or(osmanthus_guard::OsmanthusError::SystemPolicyNotInitialized)?;
    let shell = policy.monitored_shells.get(&uid).ok_or_else(|| {
        OsmanthusError::InvalidState(format!(
            "UID {uid} has no shell configured; use `sudo osmanthus policy monitor add {uid} --shell /absolute/shell`"
        ))
    })?;
    osmanthus_guard::login_shell::validate_real_shell(shell)?;

    let session_id = uuid::Uuid::new_v4().to_string();
    expect_response(
        RequestBody::SessionStart {
            session_id: session_id.clone(),
            shell: shell.display().to_string(),
        },
        |body| matches!(body, ResponseBody::SessionAccepted),
    )?;

    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let login = std::env::args_os()
        .next()
        .and_then(|value| PathBuf::from(value).file_name().map(OsString::from))
        .is_some_and(|name| name.to_string_lossy().starts_with('-'));
    let mut master_fd = -1;
    let child = unsafe {
        libc::forkpty(
            &mut master_fd,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        let mut command = Command::new(shell);
        command.env("SHELL", shell).args(arguments);
        if login {
            let name = shell
                .file_name()
                .map(|value| format!("-{}", value.to_string_lossy()))
                .unwrap_or_else(|| "-sh".to_owned());
            command.arg0(name);
        }
        let error = command.exec();
        eprintln!(
            "osmanthus-shell: failed to execute {}: {error}",
            shell.display()
        );
        unsafe { libc::_exit(126) };
    }

    let mut master = unsafe { File::from_raw_fd(master_fd) };
    copy_window_size(io::stdin().as_raw_fd(), master.as_raw_fd());
    let _terminal = TerminalMode::raw(io::stdin().as_raw_fd())?;
    let relay_result = relay(&session_id, &mut master);
    if relay_result.is_err() {
        unsafe {
            libc::kill(-child, libc::SIGKILL);
            libc::kill(child, libc::SIGKILL);
        }
    }
    let exit_code = wait_for_child(child)?;
    relay_result?;
    expect_response(
        RequestBody::SessionEnd {
            session_id,
            exit_code: i32::from(exit_code),
        },
        |body| matches!(body, ResponseBody::SessionClosed),
    )?;
    Ok(exit_code)
}

fn relay(session_id: &str, master: &mut File) -> Result<()> {
    let mut stdin_open = true;
    let mut buffer = [0_u8; BUFFER_BYTES];
    loop {
        copy_window_size(io::stdin().as_raw_fd(), master.as_raw_fd());
        let mut descriptors = [
            libc::pollfd {
                fd: if stdin_open {
                    io::stdin().as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, 250) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if descriptors[0].revents & libc::POLLIN != 0 {
            let count = io::stdin().read(&mut buffer)?;
            if count == 0 {
                stdin_open = false;
                master.write_all(&[4, 4])?;
            } else {
                record_io(session_id, SessionDirection::Input, &buffer[..count])?;
                master.write_all(&buffer[..count])?;
            }
        }
        if descriptors[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 && stdin_open {
            stdin_open = false;
            master.write_all(&[4, 4])?;
        }
        if descriptors[1].revents & libc::POLLIN != 0 {
            match master.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    record_io(session_id, SessionDirection::Output, &buffer[..count])?;
                    io::stdout().write_all(&buffer[..count])?;
                    io::stdout().flush()?;
                }
                Err(error) if error.raw_os_error() == Some(libc::EIO) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        if descriptors[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            loop {
                match master.read(&mut buffer) {
                    Ok(0) => return Ok(()),
                    Ok(count) => {
                        record_io(session_id, SessionDirection::Output, &buffer[..count])?;
                        io::stdout().write_all(&buffer[..count])?;
                        io::stdout().flush()?;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => return Ok(()),
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
}

fn record_io(session_id: &str, direction: SessionDirection, bytes: &[u8]) -> Result<()> {
    let encoded = data_encoding::BASE64.encode(bytes);
    expect_response(
        RequestBody::SessionData {
            session_id: session_id.to_owned(),
            direction,
            data_base64: encoded,
        },
        |body| matches!(body, ResponseBody::SessionDataRecorded),
    )
}

fn expect_response(body: RequestBody, expected: impl FnOnce(&ResponseBody) -> bool) -> Result<()> {
    let response = osmanthus_guard::daemon_client::request(body)?;
    if !expected(&response) {
        return Err(OsmanthusError::InvalidState(format!(
            "unexpected daemon response: {response:?}"
        )));
    }
    Ok(())
}

fn wait_for_child(child: libc::pid_t) -> Result<u8> {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(0);
            }
            return Err(error.into());
        }
    }
    if libc::WIFEXITED(status) {
        Ok(u8::try_from(libc::WEXITSTATUS(status)).unwrap_or(1))
    } else if libc::WIFSIGNALED(status) {
        Ok(u8::try_from(128 + libc::WTERMSIG(status)).unwrap_or(1))
    } else {
        Ok(1)
    }
}

fn copy_window_size(input_fd: i32, pty_fd: i32) {
    if unsafe { libc::isatty(input_fd) } != 1 {
        return;
    }
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(input_fd, libc::TIOCGWINSZ, &mut size) } == 0 {
        unsafe {
            libc::ioctl(pty_fd, libc::TIOCSWINSZ, &size);
        }
    }
}

struct TerminalMode {
    fd: i32,
    original: Option<libc::termios>,
}

impl TerminalMode {
    fn raw(fd: i32) -> Result<Self> {
        if unsafe { libc::isatty(fd) } != 1 {
            return Ok(Self { fd, original: None });
        }
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            fd,
            original: Some(original),
        })
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, original);
            }
        }
    }
}
