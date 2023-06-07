#![allow(unused)]

use std::io::Read;

use const_oid::{
    db::{rfc5280, rfc5912, Database, DB},
    ObjectIdentifier,
};
use ct_sct::sct::CT_PRECERT_SCTS;
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
    get_oid_desc(oid)
        .or(DB.by_oid(oid))
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
    let n_chunks = bytes.len() / width;

    bytes.chunks(width).enumerate().map(move |(i, chunk)| {
        let mut chunk = chunk.iter().map(|byte| format!("{byte:0>2x}:")).join("");
        if i == n_chunks {
            let _ = chunk.pop();
        }
        chunk
    })
}

fn get_oid_desc(oid: &ObjectIdentifier) -> Option<&str> {
    OID_DESCS
        .iter()
        .find(|(&id, _)| id == *oid)
        .map(|&(_, desc)| desc)
}

//TODO: convert into a phf if it grows too large
/// Contains human readable descriptions for commonly used OIDs.
const OID_DESCS: &[(&ObjectIdentifier, &str)] = &[
    (
        &rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
        "Subject Key Identifier",
    ),
    (
        &rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
        "Authority Key Identifier",
    ),
    (&rfc5280::ID_CE_KEY_USAGE, "Key Usage"),
    (&rfc5280::ID_CE_EXT_KEY_USAGE, "Extended Key Usage"),
    (&rfc5280::ID_CE_SUBJECT_ALT_NAME, "Subject Alternate Name"),
    (&rfc5912::ID_KP_CLIENT_AUTH, "Client Authentication"),
    (&rfc5912::ID_KP_SERVER_AUTH, "Server Authentication"),
    (&rfc5912::ID_CE_BASIC_CONSTRAINTS, "Basic Constraints"),
    (
        &rfc5912::ID_PE_AUTHORITY_INFO_ACCESS,
        "Authority Information Access",
    ),
    (
        &rfc5912::ID_CE_CRL_DISTRIBUTION_POINTS,
        "CRL Distribution Points",
    ),
    (&rfc5912::ID_CE_CERTIFICATE_POLICIES, "Certificate Policies"),
    (&rfc5912::ID_AD_OCSP, "OCSP"),
    (&rfc5912::ID_AD_CA_ISSUERS, "CA Issuers"),
    (&CT_PRECERT_SCTS, "CT Precertificate SCTs"),
    (
        &ObjectIdentifier::new_unwrap("2.23.140.1.1"),
        "Extended Validation (EV) Guidelines",
    ),
    (
        &ObjectIdentifier::new_unwrap("2.23.140.1.2.1"),
        "Domain Validated",
    ),
    (
        &ObjectIdentifier::new_unwrap("2.23.140.1.2.2"),
        "Organization Validated",
    ),
    (
        &ObjectIdentifier::new_unwrap("2.23.140.1.2.3"),
        "Individual Validated",
    ),
    (
        &ObjectIdentifier::new_unwrap("2.16.840.1.114412.2.1"),
        "DigiCert Extended Validation (EV) Guidelines",
    ),
];
