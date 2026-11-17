//! The identifiers of a request and of a job.

use crate::protocol::{BrokerError, refuse};
use garrison_core::hex;

/// `xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx` in lowercase.
pub(super) fn is_request_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            14 => *byte == b'4',
            19 => b"89ab".contains(byte),
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
}

/// A job ID: 32 lowercase hex digits.
pub fn is_job_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A random version-4 UUID as 32 lowercase hex digits without dashes.
pub(super) fn job_id() -> Result<String, BrokerError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| {
        log::error!("A maintenance job could not get an ID: no random numbers ({error})");
        refuse(500, "Internal broker error")
    })?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(hex::encode(&bytes))
}
