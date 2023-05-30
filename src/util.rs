#![allow(unused)]

use std::io::Read;

use const_oid::{db::DB, ObjectIdentifier};
use itertools::Itertools as _;
use x509_cert::spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};

/// Taken from <https://github.com/rustls/rustls/blob/a71223c4/rustls/src/x509.rs>.
pub(crate) fn wrap_in_asn1_len(bytes: &mut Vec<u8>) {
    let len = bytes.len();

    if len <= 0x7f {
        bytes.insert(0, len as u8);
    } else {
        bytes.insert(0, 0x80u8);
        let mut left = len;
        while left > 0 {
            let byte = (left & 0xff) as u8;
            bytes.insert(1, byte);
            bytes[0] += 1;
            left >>= 8;
        }
    }
}

/// Prepend stuff to `bytes` to put it in a DER SEQUENCE.
///
/// Taken from <https://github.com/rustls/rustls/blob/a71223c4/rustls/src/x509.rs>.
pub(crate) fn wrap_in_sequence(bytes: &mut Vec<u8>) {
    wrap_in_asn1_len(bytes);
    bytes.insert(0, u8::from(der::Tag::Sequence));
}

#[track_caller]
pub(crate) fn assert_null_params(alg: &AlgorithmIdentifierOwned) {
    assert!(alg.parameters.is_none() || alg.parameters.as_ref().unwrap().is_null());
}

pub(crate) fn oid_desc_or_raw(oid: &ObjectIdentifier) -> String {
    DB.by_oid(oid)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| oid.to_string())
}

pub(crate) fn duration_since_now_fmt(time: x509_cert::time::Time) -> String {
    use chrono::{DateTime, Utc};

    let ts = time.to_unix_duration().as_secs() as i64;

    let date = DateTime::<Utc>::from_utc(
        chrono::NaiveDateTime::from_timestamp_opt(ts, 0).unwrap(),
        Utc,
    );
    let now = Utc::now();

    let duration = if now > date { now - date } else { date - now };

    let days = duration.num_days();

    if now > date {
        format!("{} days ago", days)
    } else {
        format!("in {} days", days)
    }
}

pub(crate) fn openssl_hex(bytes: &[u8], width: usize) -> impl Iterator<Item = String> + '_ {
    let bytes = if bytes.len() < width {
        bytes
    } else {
        &bytes[(bytes.len() - width)..]
    };

    let n_chunks = bytes.len() / width;

    bytes.chunks(width).enumerate().map(move |(i, chunk)| {
        let mut chunk = chunk.iter().map(|byte| format!("{byte:0>2x}:")).join("");
        if i == n_chunks {
            let _ = chunk.pop();
        }
        chunk
    })
}
