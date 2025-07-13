use std::{borrow::Cow, net::IpAddr};

use const_oid::AssociatedOid as _;
use der::Decode;
use itertools::Itertools;
use x509_cert::ext::{
    pkix::{self, crl::dp, name::GeneralName, sct, AuthorityKeyIdentifier},
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
        pkix::CrlDistributionPoints::OID => fmt_crl_distribution_points(ext),
        sct::SignedCertificateTimestampList::OID => fmt_sct_list(ext),
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

fn fmt_crl_distribution_points(ext: &Extension) -> String {
    let crl_dp = pkix::CrlDistributionPoints::from_der(ext.extn_value.as_bytes()).unwrap();
    crl_dp.0.iter().map(fmt_crl_distribution_point).join(", ")
}

fn fmt_crl_distribution_point(dp: &dp::DistributionPoint) -> String {
    let name = fmt_dp_name(dp);
    let issuer = fmt_dp_crl_issuer(dp);
    let reason = fmt_dp_reasons(dp);
    format!("{name}{issuer}{reason}")
}

fn fmt_dp_name(dp: &dp::DistributionPoint) -> String {
    if let Some(ref dp_name) = dp.distribution_point {
        match dp_name {
            pkix::name::DistributionPointName::FullName(names) => {
                format!(
                    "FullName:\n      {}",
                    names.iter().map(fmt_general_name).join(", ")
                )
            }
            pkix::name::DistributionPointName::NameRelativeToCRLIssuer(name) => {
                format!("RelativeName:\n      {name}")
            }
        }
    } else {
        String::new()
    }
}

fn fmt_dp_crl_issuer(dp: &dp::DistributionPoint) -> String {
    if let Some(ref issuer) = dp.crl_issuer {
        format!(
            "{}Issuer: {}",
            if dp.distribution_point.is_some() {
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

fn fmt_dp_reasons(dp: &dp::DistributionPoint) -> String {
    if let Some(ref reasons) = dp.reasons {
        format!(
            "{}Reasons: {}",
            if dp.distribution_point.is_some() || dp.crl_issuer.is_some() {
                "\n    "
            } else {
                "    "
            },
            reasons.into_iter().map(fmt_reason).join(", ")
        )
    } else {
        String::new()
    }
}

fn fmt_reason(reason: dp::Reasons) -> &'static str {
    match reason {
        dp::Reasons::Unused => "Unused",
        dp::Reasons::KeyCompromise => "KeyCompromise",
        dp::Reasons::CaCompromise => "CaCompromise",
        dp::Reasons::AffiliationChanged => "AffiliationChanged",
        dp::Reasons::Superseded => "Superseded",
        dp::Reasons::CessationOfOperation => "CessationOfOperation",
        dp::Reasons::CertificateHold => "CertificateHold",
        dp::Reasons::PrivilegeWithdrawn => "PrivilegeWithdrawn",
        dp::Reasons::AaCompromise => "AaCompromise",
    }
}

fn fmt_sct_list(ext: &Extension) -> String {
    sct::SignedCertificateTimestampList::from_der(ext.extn_value.as_bytes())
        .expect("Failed to deserialize SCT list")
        .parse_timestamps()
        .expect("Failed to parse SCT timestamps")
        .into_iter()
        .map(|ser_sct| {
            ser_sct
                .parse_timestamp()
                .expect("Failed to deserialize SCT timestamp")
        })
        .map(fmt_sct)
        .join("\n    ")
}

fn fmt_sct(sct: sct::SignedCertificateTimestamp) -> String {
    let extensions = openssl_hex(sct.extensions.as_slice(), 16).join("\n                  ");
    format!(
        "Signed Certificate Timestamp:\n      Version   : {:?}\n      Log ID    : {}\n      Timestamp : {}\n      Extensions: {}\n      Signature : {}\n                  {}",
        sct.version,
        openssl_hex(&sct.log_id.key_id, 16).join("\n                  "),
        sct.timestamp().expect("SCT timestamp is outside supported range"),
        if extensions.is_empty() {
            "none"
        } else {
            &extensions
        },
        fmt_signature_and_hash_alg(&sct.signature.algorithm),
        openssl_hex(sct.signature.signature.as_slice(), 16).join("\n                  "),
    )
}

fn fmt_signature_and_hash_alg(alg: &sct::SignatureAndHashAlgorithm) -> String {
    format!(
        "{}-with-{}",
        format!("{:?}", alg.signature).to_ascii_uppercase(),
        format!("{:?}", alg.hash).to_ascii_uppercase(),
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
    let path_len = constraints
        .path_len_constraint
        .map_or(Cow::Borrowed("None"), |c| Cow::Owned(format!("{c}")));
    format!(
        "CA: {}\n    Path Length Constraint: {path_len}",
        constraints.ca
    )
}

fn fmt_certificate_policies(ext: &Extension) -> String {
    let policies = pkix::CertificatePolicies::from_der(ext.extn_value.as_bytes()).unwrap();
    policies
        .0
        .into_iter()
        .map(|info| {
            let qualifiers = info
                .policy_qualifiers
                .map(|qualifiers| {
                    format!(
                        " (qualifiers: {})",
                        qualifiers
                            .into_iter()
                            .map(|qualifier| oid_desc_or_raw(&qualifier.policy_qualifier_id))
                            .join(", ")
                    )
                })
                .unwrap_or_default();

            format!("{}{}", oid_desc_or_raw(&info.policy_identifier), qualifiers)
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

//TODO: remove debug format for OtherName, EdiPartyName
fn fmt_general_name(name: &GeneralName) -> String {
    match name {
        GeneralName::OtherName(other) => format!("OTHER{other:?}"),
        GeneralName::Rfc822Name(rfc) => format!("RFC:{}", rfc.as_str()),
        GeneralName::DnsName(dns) => format!("DNS:{}", dns.as_str()),
        GeneralName::DirectoryName(dir) => format!("DIR:{dir}"),
        GeneralName::EdiPartyName(edi) => format!("EDI:{edi:?}"),
        GeneralName::UniformResourceIdentifier(uri) => format!("URI:{}", uri.as_str()),
        GeneralName::IpAddress(ip) => match ip_try_from_bytes(ip.as_bytes()) {
            Some(ip) => format!("IP:{ip}"),
            None => format!("IP:{ip:?}"),
        },
        GeneralName::RegisteredId(id) => oid_desc_or_raw(id),
    }
}

fn ip_try_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    Some(match bytes.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(bytes).unwrap()),
        16 => IpAddr::from(<[u8; 16]>::try_from(bytes).unwrap()),
        _ => return None,
    })
}
