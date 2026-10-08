use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::protocol::{PROTOCOL_VERSION, Request, RequestBody, ResponseBody};
use crate::{OsmanthusError, Result};

const DAEMON_IO_TIMEOUT: Duration = Duration::from_secs(2);

pub fn request(body: RequestBody) -> Result<ResponseBody> {
    let request = Request {
        protocol_version: PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        body,
    };
    let mut stream = UnixStream::connect(crate::linux_daemon::SOCKET_PATH).map_err(|error| {
        OsmanthusError::InvalidState(format!(
            "cannot connect to osmanthusd at {}: {error}",
            crate::linux_daemon::SOCKET_PATH
        ))
    })?;
    stream.set_read_timeout(Some(DAEMON_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(DAEMON_IO_TIMEOUT))?;
    crate::protocol::write_request(&mut stream, &request)?;
    let response = crate::protocol::read_response(&mut BufReader::new(stream))?;
    if response.request_id != request.request_id {
        return Err(OsmanthusError::InvalidState(
            "daemon response request ID does not match".to_owned(),
        ));
    }
    match response.body {
        ResponseBody::Error { code, message: _ } if code == "invalid_code" => {
            Err(OsmanthusError::InvalidCode)
        }
        ResponseBody::Error { message, .. } => Err(OsmanthusError::InvalidState(message)),
        body => Ok(body),
    }
}
