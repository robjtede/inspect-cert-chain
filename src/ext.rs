use const_oid::{db::DB, AssociatedOid as _, ObjectIdentifier};
use ct_sct::sct;
use der::Decode;
use itertools::Itertools;
use x509_cert::ext::{
    pkix::{self, name::GeneralName, AuthorityKeyIdentifier},
    Extension,
};

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
        pkix::AuthorityKeyIdentifier::OID => fmt_authority_key_identifier(ext),
        sct::SctList::OID => fmt_sct_list(ext),
        _ => openssl_hex(ext.extn_value.as_bytes(), 80).join("\n    "),
    }
}

fn fmt_key_usage(ext: &Extension) -> String {
    let key_usage = pkix::KeyUsage::from_der(ext.extn_value.as_bytes()).unwrap();
    key_usage
        .0
        .into_iter()
        .map(|ku| format!("{ku:?}"))
        .join(", ")
}

fn fmt_extended_key_usage(ext: &Extension) -> String {
    let key_usage = pkix::ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).unwrap();
    key_usage.0.iter().map(oid_desc_or_raw).join("\n    ")
}

fn fmt_authority_key_identifier(ext: &Extension) -> String {
    let aki = pkix::AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()).unwrap();
    let key_id = fmt_aki_key_id(&aki);
    let issuer = fmt_aki_issuer(&aki);
    let serial = fmt_aki_serial(&aki);
    format!("{key_id}{issuer}{serial}")
}

fn fmt_aki_key_id(aki: &AuthorityKeyIdentifier) -> String {
    if let Some(ref key_id) = aki.key_identifier {
        format!("KeyId: {}", openssl_hex(key_id.as_bytes(), 20).join("\n"))
    } else {
        String::new()
    }
}

fn fmt_aki_issuer(aki: &AuthorityKeyIdentifier) -> String {
    if let Some(ref issuer) = aki.authority_cert_issuer {
        format!(
            "{}Issuer: {}",
            if aki.key_identifier.is_some() {
                "\n    "
            } else {
                "    "
            },
            issuer.iter().map(fmt_general_name).join(", ")
        )
    } else {
        String::new()
    }
}

fn fmt_aki_serial(aki: &AuthorityKeyIdentifier) -> String {
    if let Some(ref serial) = aki.authority_cert_serial_number {
        format!(
            "{}Serial: {}",
            if aki.key_identifier.is_some() || aki.authority_cert_issuer.is_some() {
                "\n    "
            } else {
                "    "
            },
            openssl_hex(serial.as_bytes(), 20).join("\n")
        )
    } else {
        String::new()
    }
}

fn fmt_sct_list(ext: &Extension) -> String {
    let sct_list = sct::SctList::from_der(ext.extn_value.as_bytes()).unwrap();
    let list =
        sct::TlsSctList::from_sct_list(&sct_list).expect("Failed to deserialize tls sct list");
    list.scts.iter().map(fmt_sct).join("\n    ")
}

fn fmt_sct(sct: &sct::TlsSct) -> String {
    let extensions = openssl_hex(&sct.extensions, 16).join("\n                  ");
    format!(
        "Signed Certificate Timestamp:\n      Version   : {}\n      Log ID    : {}\n      Timestamp : {}\n      Extensions: {}\n      Signature : {}\n                  {}",
        sct.version,
        openssl_hex(&sct.log_id, 16).join("\n                  "),
        sct.timestamp,
        if extensions.is_empty() { "none" } else { &extensions },
        sct.sign.sign_and_hash_algo,
        openssl_hex(&sct.sign.sign, 16).join("\n                  "),
    )
}

fn fmt_authority_info_access_syntax(ext: &Extension) -> String {
    let authority_info_access =
        pkix::AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()).unwrap();

    authority_info_access
        .0
        .into_iter()
        .map(|access_description| {
            format!(
                "{}  {}",
                oid_desc_or_raw(&access_description.access_method),
                fmt_general_name(&access_description.access_location)
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
    san.0
        .into_iter()
        .map(|name| fmt_general_name(&name))
        .join(", ")
}

fn fmt_subject_key_identifier(ext: &Extension) -> String {
    let ski = pkix::SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).unwrap();
    let mut iter = openssl_hex(ski.0.as_bytes(), 20);
    iter.join("\n    ")
}

//TODO: remove debug format for OtherName, EdiPartyName and IpAddress
fn fmt_general_name(name: &GeneralName) -> String {
    match name {
        GeneralName::OtherName(other) => format!("OTHER{:?}", other),
        GeneralName::Rfc822Name(rfc) => format!("RFC:{}", rfc.as_str()),
        GeneralName::DnsName(dns) => format!("DNS:{}", dns.as_str()),
        GeneralName::DirectoryName(dir) => format!("DIR:{}", dir),
        GeneralName::EdiPartyName(edi) => format!("EDI:{:?}", edi),
        GeneralName::UniformResourceIdentifier(uri) => format!("URI:{}", uri.as_str()),
        GeneralName::IpAddress(ip) => format!("IP:{:?}", ip),
        GeneralName::RegisteredId(id) => oid_desc_or_raw(id),
    }
}
