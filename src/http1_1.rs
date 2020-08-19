
use std::fmt;
use std::error::Error;
use http_types::{
    Request,
    Response,
    StatusCode,
};

// https://github.com/snapview/tungstenite-rs/blob/0c429cba9485e8f5efe9e51a8c088fcade93f35c/src/handshake/mod.rs#L115
use sha1::{Digest, Sha1};
use base64;
/// Turns a Sec-WebSocket-Key into a Sec-WebSocket-Accept.
pub fn convert_key(input: &[u8]) -> String {
    // ... field is constructed by concatenating /key/ ...
    // ... with the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" (RFC 6455)
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut sha1 = Sha1::default();
    sha1.input(input);
    sha1.input(WS_GUID);
    base64::encode(&sha1.result())
}

#[derive(Debug)]
pub enum HandshakeError {
    MissingHeader(&'static str),
    InvalidHeaderValue {
        header: &'static str,
        expected: Option<&'static str>,
        found: String,
    },
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingHeader(header) => {
                write!(f, "Missing required header `{}`", header)
            }
            Self::InvalidHeaderValue { header, expected, found } => {
                write!(f, "Invalid value `{}` for header `{}`", found, header)?;
                if let Some(expected) = expected {
                    write!(f, ", expected `{}`", expected)?;
                }
                Ok(())
            }
        }
    }
}

impl Error for HandshakeError {}

#[allow(dead_code)]
pub struct HandshakeInfo<'a> {
    key: &'a str,
    extensions: Vec<&'a str>,
    protocols: Vec<&'a str>,
}

impl HandshakeInfo<'_> {
    pub fn make_response(&self) -> Response {
        let mut res = Response::new(StatusCode::SwitchingProtocols);
        
        let accept = convert_key(self.key.as_bytes());
        res.insert_header("Upgrade", "websocket");
        res.insert_header("Connection", "Upgrade");
        res.insert_header("Sec-WebSocket-Accept", accept);
        
        res
    }
}

fn assert_header<'a>(req: &'a Request, header: &'static str, expected: &'static str) -> Result<(), HandshakeError> {
    let value = req.header(header)
        .ok_or_else(|| HandshakeError::MissingHeader(header))?
        .last()
        .as_str()
        ;
    if value != expected {
        return Err(HandshakeError::InvalidHeaderValue {
            header,
            expected: Some(expected),
            found: value.to_string()
        })
    }
    
    Ok(())
}

pub fn check_request_headers(request: &Request) -> Result<HandshakeInfo, HandshakeError> {
    assert_header(request, "Connection", "Upgrade")?;
    assert_header(request, "Upgrade", "websocket")?;
    assert_header(request, "Sec-WebSocket-Version", "13")?;
    
    let key = request
        .header("Sec-WebSocket-Key")
        .ok_or_else(|| HandshakeError::MissingHeader("Sec-WebSocket-Key"))?
        .last()
        .as_str()
        ;
    
    // grammar for headers
    // https://tools.ietf.org/html/rfc6455#section-4.3
    // https://tools.ietf.org/html/rfc6455#section-9.1
    
    let mut extensions = Vec::new();
    if let Some(values) = request.header("Sec-WebSocket-Extensions") {
        // don't use .iter since it explicitly doesn't guarantee ordering
        let mut i = 0;
        while let Some(value) = values.get(i) {
            let value = value.as_str();
            for ext_string in value.split(",") {
                // skip extensions with parameters for now
                if ext_string.contains(";") {
                    continue
                }
                
                let ext_string = ext_string.trim();
                
                extensions.push(ext_string);
            }
            
            i += 1;
        }
    }
    
    let mut protocols = Vec::new();
    if let Some(values) = request.header("Sec-WebSocket-Protocol") {
        // don't use .iter since it explicitly doesn't guarantee ordering
        let mut i = 0;
        while let Some(value) = values.get(i) {
            let value = value.as_str();
            for proto_string in value.split(",") {
                protocols.push(proto_string.trim());
            }
            
            i += 1;
        }
    }
    
    Ok(HandshakeInfo {
        key,
        extensions,
        protocols,
    })
}
