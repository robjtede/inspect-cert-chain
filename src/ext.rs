use const_oid::{db::DB, AssociatedOid as _, ObjectIdentifier};
use der::Decode;
use itertools::Itertools;
use x509_cert::ext::{pkix, Extension};

use crate::util::{oid_desc_or_raw, openssl_hex};

pub(crate) fn interpret_val(ext: &Extension) -> String {
    match ext.extn_id {
        pkix::SubjectKeyIdentifier::OID => fmt_subject_key_identifier(ext),
        pkix::SubjectAltName::OID => fmt_subject_alt_name(ext),
        pkix::CertificatePolicies::OID => fmt_certificate_policies(ext),
        pkix::BasicConstraints::OID => fmt_basic_constraints(ext),
        pkix::AuthorityInfoAccessSyntax::OID => fmt_authority_info_access_syntax(ext),
        pkix::KeyUsage::OID => fmt_key_usage(ext),
        pkix::ExtendedKeyUsage::OID => fmt_extended_key_usage(ext),
        _ => openssl_hex(ext.extn_value.as_bytes(), 80).join("\n    "),
    }
}

fn fmt_key_usage(ext: &Extension) -> String {
    let key_usage = pkix::KeyUsage::from_der(ext.extn_value.as_bytes()).unwrap();
    format!("{:?}", key_usage.0)
}

fn fmt_extended_key_usage(ext: &Extension) -> String {
    let key_usage = pkix::ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).unwrap();
    key_usage.0.iter().map(oid_desc_or_raw).join("\n    ")
}

fn fmt_authority_info_access_syntax(ext: &Extension) -> String {
    let authority_info_access =
        pkix::AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()).unwrap();

    authority_info_access
        .0
        .into_iter()
        .map(|access_description| {
            format!(
                "{}  {:?}",
                oid_desc_or_raw(&access_description.access_method),
                access_description.access_location
            )
        })
        .join("\n    ")
}

fn fmt_basic_constraints(ext: &Extension) -> String {
    let constraints = pkix::BasicConstraints::from_der(ext.extn_value.as_bytes()).unwrap();
    format!(
        "CA: {}\n    Path Length Constraint: {:?}",
        constraints.ca, constraints.path_len_constraint
    )
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
