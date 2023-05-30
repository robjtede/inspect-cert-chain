use const_oid::{db::DB, AssociatedOid as _, ObjectIdentifier};
use der::Decode;
use itertools::Itertools;
use x509_cert::ext::{pkix, Extension};

use crate::util::openssl_hex;

pub(crate) fn interpret_val(ext: &Extension) -> String {
    match ext.extn_id {
        pkix::SubjectKeyIdentifier::OID => fmt_subject_key_identifier(ext),
        pkix::SubjectAltName::OID => fmt_subject_alt_name(ext),
        pkix::CertificatePolicies::OID => fmt_certificate_policies(ext),
        _ => openssl_hex(ext.extn_value.as_bytes(), 80).join("\n    "),
    }
}

fn fmt_certificate_policies(ext: &Extension) -> String {
    const DV: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.140.1.2.1");

    let policies = pkix::CertificatePolicies::from_der(ext.extn_value.as_bytes()).unwrap();
    policies
        .0
        .into_iter()
        .map(|info| {
            format!(
                "{}{}",
                match info.policy_identifier {
                    DV => "domain-validated".to_owned(),
                    _ => info.policy_identifier.to_string(),
                },
                if info.policy_qualifiers.is_some() {
                    " (has qualifiers)"
                } else {
                    ""
                }
            )
        })
        .join("\n    ")
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
