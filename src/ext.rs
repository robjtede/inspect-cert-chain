use const_oid::AssociatedOid as _;
use der::Decode;
use itertools::Itertools;
use x509_cert::ext::{pkix, Extension};

use crate::util::openssl_hex;

pub(crate) fn interpret_val(ext: &Extension) -> String {
    match ext.extn_id {
        pkix::SubjectKeyIdentifier::OID => fmt_subject_key_identifier(ext),
        pkix::SubjectAltName::OID => fmt_subject_alt_name(ext),
        _ => openssl_hex(ext.extn_value.as_bytes(), 80).join("\n    "),
    }
}

fn fmt_subject_alt_name(ext: &Extension) -> String {
    let san = pkix::SubjectAltName::from_der(ext.extn_value.as_bytes()).unwrap();
    san.0.into_iter().map(|name| format!("{name:?}")).join(", ")
}

fn fmt_subject_key_identifier(ext: &Extension) -> String {
    let ski = pkix::SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).unwrap();
    let mut iter = openssl_hex(ski.0.as_bytes(), 20);
    iter.join("\n    ")
}
