use std::io;

use byteorder::{BigEndian, ByteOrder as _};
use const_oid::{
    db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION},
    ObjectIdentifier,
};
use der::Decode as _;
use itertools::Itertools as _;
use x509_cert::Certificate;

use crate::{ext, util};

pub(crate) fn write_cert_info(cert: &Certificate, mut wrt: impl io::Write) -> io::Result<()> {
    writeln!(wrt, "Certificate")?;
    writeln!(wrt, "===========")?;

    let tbs = &cert.tbs_certificate;

    let tbs_cert = &tbs;
    writeln!(wrt, "Subject: {}", tbs_cert.subject)?;

    writeln!(wrt, "Issuer: {}", tbs.issuer)?;

    writeln!(wrt, "Version: {:?}", tbs.version)?;
    writeln!(
        wrt,
        "Serial Number:\n  {}",
        util::openssl_hex(tbs.serial_number.as_bytes(), 20).join("\n  ")
    )?;

    writeln!(
        wrt,
        "Signature Algorithm: {}",
        util::oid_desc_or_raw(&cert.signature_algorithm.oid)
    )?;
    util::assert_null_params(&cert.signature_algorithm);

    // TODO: doesn't work ?
    writeln!(
        wrt,
        "Issuer Serial Number:\n  {}",
        tbs.issuer_unique_id
            .as_ref()
            .map(|serial| util::openssl_hex(serial.as_bytes().unwrap(), 20).join("\n  "))
            .unwrap_or_else(|| "<unknown>".to_owned())
    )?;
    writeln!(wrt, "Validity:")?;
    writeln!(
        wrt,
        "  Not Before: {} ({})",
        tbs.validity.not_before,
        util::duration_since_now_fmt(tbs.validity.not_before),
    )?;
    writeln!(
        wrt,
        "  Not After: {} ({})",
        tbs.validity.not_after,
        util::duration_since_now_fmt(tbs.validity.not_after),
    )?;

    // if let Some(name_constraints) = anchor.name_constraints {
    //     writeln!(w, "Name Constraints: {:?}", name_constraints);
    // }

    writeln!(wrt, "Subject Public Key Info:")?;

    let spki = &tbs_cert.subject_public_key_info;
    let alg = &spki.algorithm;

    match () {
        _ if alg.oid == ID_EC_PUBLIC_KEY => {
            let ec_subtype = alg
                .parameters
                .as_ref()
                .unwrap()
                .decode_as::<ObjectIdentifier>()
                .unwrap();

            let ec_type = util::oid_desc_or_raw(&alg.oid);
            let ec_subtype = util::oid_desc_or_raw(&ec_subtype);

            let public_key_bytes = spki.subject_public_key.as_bytes().unwrap();
            let public_key = util::openssl_hex(public_key_bytes, 15).join("\n    ");

            writeln!(wrt, "  Algorithm: {ec_type} ({ec_subtype})")?;
            writeln!(wrt, "  Public Key:\n    {public_key}")?;
        }

        _ if alg.oid == RSA_ENCRYPTION => {
            let algorithm = util::oid_desc_or_raw(&alg.oid);
            writeln!(wrt, "  Algorithm: {algorithm}")?;

            let rsa_details =
                pkcs1::RsaPublicKey::from_der(spki.subject_public_key.as_bytes().unwrap()).unwrap();

            writeln!(wrt, "  RSA:")?;

            let exp_bytes = rsa_details.public_exponent.as_bytes();
            let exp = BigEndian::read_uint(exp_bytes, exp_bytes.len());
            writeln!(wrt, "    Exponent: {exp} (0x{exp:0x})")?;
            let mod_bytes = rsa_details.modulus.as_bytes();
            writeln!(
                wrt,
                "    Modulus({} bit):\n      {}",
                mod_bytes.len() * 8,
                util::openssl_hex(mod_bytes, 32).join("\n      ")
            )?;
        }

        _ => {
            let alg = util::oid_desc_or_raw(&alg.oid);
            writeln!(wrt, "  Algorithm: {alg}")?;
        }
    }

    if let Some(extensions) = &tbs.extensions {
        writeln!(wrt, "Extensions:")?;

        for ext in extensions {
            writeln!(
                wrt,
                "  ID: {}{}",
                util::oid_desc_or_raw(&ext.extn_id),
                if ext.critical { " (critical)" } else { "" }
            )?;
            writeln!(wrt, "  Extension value:\n    {}", ext::interpret_val(ext))?;
            writeln!(wrt)?;
        }
    }

    writeln!(wrt, "Signature:")?;
    writeln!(
        wrt,
        "  {}",
        util::openssl_hex(cert.signature.as_bytes().unwrap(), 20).join("\n  ")
    )?;

    Ok(())
}
