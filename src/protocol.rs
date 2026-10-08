use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::enforcement::{
    EnforcementDecision, MaintenanceLease, ProtectedAction, ResourceOperation,
};
use crate::{OsmanthusError, Result};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub protocol_version: u32,
    pub request_id: String,
    #[serde(flatten)]
    pub body: RequestBody,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(OsmanthusError::InvalidState(format!(
                "unsupported daemon protocol version: {}",
                self.protocol_version
            )));
        }
        if self.request_id.is_empty()
            || self.request_id.len() > 64
            || !self
                .request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(OsmanthusError::InvalidState(
                "daemon request ID must be 1-64 ASCII letters, digits, '-' or '_'".to_owned(),
            ));
        }
        match &self.body {
            RequestBody::Health | RequestBody::MaintenanceList => Ok(()),
            RequestBody::Decommission { authenticator_code } => {
                validate_authenticator_code(authenticator_code)
            }
            RequestBody::PolicyReload { policy } => policy.validate(),
            RequestBody::SessionStart { session_id, shell } => {
                validate_session_id(session_id)?;
                if shell.is_empty()
                    || shell.len() > 4096
                    || !std::path::Path::new(shell).is_absolute()
                {
                    return Err(OsmanthusError::InvalidState(
                        "session shell must be an absolute path of at most 4096 bytes".to_owned(),
                    ));
                }
                Ok(())
            }
            RequestBody::SessionData {
                session_id,
                data_base64,
                ..
            } => {
                validate_session_id(session_id)?;
                if data_base64.len() > 49_152 {
                    return Err(OsmanthusError::InvalidState(
                        "session I/O frame is too large".to_owned(),
                    ));
                }
                data_encoding::BASE64
                    .decode(data_base64.as_bytes())
                    .map_err(|_| {
                        OsmanthusError::InvalidState(
                            "session I/O frame is not valid base64".to_owned(),
                        )
                    })?;
                Ok(())
            }
            RequestBody::SessionEnd {
                session_id,
                exit_code,
            } => {
                validate_session_id(session_id)?;
                if !(-1..=255).contains(exit_code) {
                    return Err(OsmanthusError::InvalidState(
                        "session exit code is outside the supported range".to_owned(),
                    ));
                }
                Ok(())
            }
            RequestBody::Evaluate {
                session_id,
                operation,
            } => {
                validate_session_id(session_id)?;
                ResourceOperation::new(operation.action, &operation.target)?;
                Ok(())
            }
            RequestBody::MaintenanceGrant {
                scope,
                actions,
                ttl_seconds,
                authenticator_code,
            } => {
                if actions.is_empty() || actions.len() > 5 {
                    return Err(OsmanthusError::InvalidState(
                        "maintenance grant requires 1-5 operation classes".to_owned(),
                    ));
                }
                ResourceOperation::new(actions[0], scope)?;
                if !(1..=crate::enforcement::MAX_MAINTENANCE_SECONDS).contains(ttl_seconds) {
                    return Err(OsmanthusError::InvalidState(
                        "maintenance grant TTL is outside the supported range".to_owned(),
                    ));
                }
                validate_authenticator_code(authenticator_code)
            }
            RequestBody::MaintenanceRevoke {
                lease_id,
                authenticator_code,
            } => {
                uuid::Uuid::parse_str(lease_id).map_err(|_| {
                    OsmanthusError::InvalidState("maintenance lease ID is invalid".to_owned())
                })?;
                validate_authenticator_code(authenticator_code)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequestBody {
    Health,
    Evaluate {
        session_id: String,
        operation: ResourceOperation,
    },
    MaintenanceGrant {
        scope: std::path::PathBuf,
        actions: Vec<ProtectedAction>,
        ttl_seconds: i64,
        authenticator_code: String,
    },
    MaintenanceRevoke {
        lease_id: String,
        authenticator_code: String,
    },
    MaintenanceList,
    Decommission {
        authenticator_code: String,
    },
    PolicyReload {
        policy: crate::enforcement::EnforcementPolicy,
    },
    SessionStart {
        session_id: String,
        shell: String,
    },
    SessionData {
        session_id: String,
        direction: SessionDirection,
        data_base64: String,
    },
    SessionEnd {
        session_id: String,
        exit_code: i32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionDirection {
    Input,
    Output,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub protocol_version: u32,
    pub request_id: String,
    #[serde(flatten)]
    pub body: ResponseBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseBody {
    Health {
        daemon_version: String,
        backend: BackendState,
    },
    Decision {
        decision: EnforcementDecision,
    },
    MaintenanceGranted {
        lease_id: String,
        expires_at_unix: i64,
    },
    MaintenanceRevoked,
    MaintenanceList {
        leases: Vec<MaintenanceLease>,
    },
    PolicyReloaded,
    Decommissioned,
    SessionAccepted,
    SessionDataRecorded,
    SessionClosed,
    Error {
        code: String,
        message: String,
    },
}

fn validate_authenticator_code(code: &str) -> Result<()> {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OsmanthusError::InvalidCode);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendState {
    Unavailable,
    ObserveOnly,
    Enforcing,
}

pub fn read_request(reader: &mut impl BufRead) -> Result<Option<Request>> {
    let Some(frame) = read_frame(reader, "request")? else {
        return Ok(None);
    };
    let request: Request = serde_json::from_slice(&frame)?;
    request.validate()?;
    Ok(Some(request))
}

fn read_frame(reader: &mut impl BufRead, kind: &str) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            return Err(OsmanthusError::InvalidState(format!(
                "daemon {kind} is not newline terminated"
            )));
        }
        let chunk_length = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if frame.len() + chunk_length > MAX_FRAME_BYTES {
            return Err(OsmanthusError::InvalidState(format!(
                "daemon {kind} exceeds {MAX_FRAME_BYTES} bytes"
            )));
        }
        frame.extend_from_slice(&available[..chunk_length]);
        reader.consume(chunk_length);
        if frame.ends_with(b"\n") {
            break;
        }
    }
    frame.pop();
    Ok(Some(frame))
}

pub fn write_response(writer: &mut impl Write, response: &Response) -> Result<()> {
    let mut frame = serde_json::to_vec(response)?;
    if frame.len() + 1 > MAX_FRAME_BYTES {
        return Err(OsmanthusError::InvalidState(
            "daemon response exceeds the frame limit".to_owned(),
        ));
    }
    frame.push(b'\n');
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

pub fn read_response(reader: &mut impl BufRead) -> Result<Response> {
    let frame = read_frame(reader, "response")?.ok_or_else(|| {
        OsmanthusError::InvalidState("daemon closed the connection without a response".to_owned())
    })?;
    let response: Response = serde_json::from_slice(&frame)?;
    if response.protocol_version != PROTOCOL_VERSION {
        return Err(OsmanthusError::InvalidState(format!(
            "unsupported daemon response protocol version: {}",
            response.protocol_version
        )));
    }
    Ok(response)
}

pub fn write_request(writer: &mut impl Write, request: &Request) -> Result<()> {
    request.validate()?;
    let mut frame = serde_json::to_vec(request)?;
    if frame.len() + 1 > MAX_FRAME_BYTES {
        return Err(OsmanthusError::InvalidState(
            "daemon request exceeds the frame limit".to_owned(),
        ));
    }
    frame.push(b'\n');
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

fn validate_session_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(OsmanthusError::InvalidState(
            "session ID must be 1-128 ASCII letters, digits, '-', '_' or '.'".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    #[test]
    fn bounded_json_line_protocol_round_trips_an_evaluation() {
        let request = Request {
            protocol_version: PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            body: RequestBody::Evaluate {
                session_id: "ssh.1000.42".to_owned(),
                operation: ResourceOperation::new(ProtectedAction::Delete, "/var/www/releases/old")
                    .unwrap(),
            },
        };
        let mut encoded = serde_json::to_vec(&request).unwrap();
        encoded.push(b'\n');
        let decoded = read_request(&mut BufReader::new(Cursor::new(encoded)))
            .unwrap()
            .unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn rejects_unterminated_oversized_and_wrong_version_requests() {
        assert!(
            read_request(&mut BufReader::new(Cursor::new(
                br#"{"protocol_version":1}"#
            )))
            .is_err()
        );
        let oversized = vec![b'a'; MAX_FRAME_BYTES + 1];
        assert!(read_request(&mut BufReader::new(Cursor::new(oversized))).is_err());
        let request = Request {
            protocol_version: PROTOCOL_VERSION + 1,
            request_id: "request-1".to_owned(),
            body: RequestBody::Health,
        };
        let mut encoded = serde_json::to_vec(&request).unwrap();
        encoded.push(b'\n');
        assert!(read_request(&mut BufReader::new(Cursor::new(encoded))).is_err());
    }

    #[test]
    fn response_writer_adds_one_frame_terminator() {
        let response = Response {
            protocol_version: PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            body: ResponseBody::Health {
                daemon_version: "0.2.0".to_owned(),
                backend: BackendState::ObserveOnly,
            },
        };
        let mut encoded = Vec::new();
        write_response(&mut encoded, &response).unwrap();
        assert_eq!(encoded.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(encoded.ends_with(b"\n"));
    }

    #[test]
    fn maintenance_requests_require_bounded_numeric_codes() {
        let request = Request {
            protocol_version: PROTOCOL_VERSION,
            request_id: "maintenance-1".to_owned(),
            body: RequestBody::MaintenanceGrant {
                scope: "/var/www".into(),
                actions: vec![ProtectedAction::Delete],
                ttl_seconds: 300,
                authenticator_code: "abcdef".to_owned(),
            },
        };
        assert!(matches!(
            request.validate(),
            Err(OsmanthusError::InvalidCode)
        ));

        let decommission = Request {
            protocol_version: PROTOCOL_VERSION,
            request_id: "decommission-1".to_owned(),
            body: RequestBody::Decommission {
                authenticator_code: "12345x".to_owned(),
            },
        };
        assert!(matches!(
            decommission.validate(),
            Err(OsmanthusError::InvalidCode)
        ));
    }
}
