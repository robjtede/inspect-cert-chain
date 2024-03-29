use byteorder::{BigEndian, ByteOrder as _};
use const_oid::{
    db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION},
    ObjectIdentifier,
};
use der::Decode as _;
use itertools::Itertools as _;
use x509_cert::Certificate;

use crate::{ext, util};

pub(crate) fn print_cert_info(cert: &Certificate) {
    println!("Certificate");
    println!("===========");

    let tbs = &cert.tbs_certificate;

    let tbs_cert = &tbs;
    println!("Subject: {}", tbs_cert.subject);

    println!("Issuer: {}", tbs.issuer);

    println!("Version: {:?}", tbs.version);
    println!(
        "Serial Number:\n  {}",
        util::openssl_hex(tbs.serial_number.as_bytes(), 20).join("\n  ")
    );

    println!(
        "Signature Algorithm: {}",
        util::oid_desc_or_raw(&cert.signature_algorithm.oid)
    );
    util::assert_null_params(&cert.signature_algorithm);

    // TODO: doesn't work ?
    println!(
        "Issuer Serial Number:\n  {}",
        tbs.issuer_unique_id
            .as_ref()
            .map(|serial| util::openssl_hex(serial.as_bytes().unwrap(), 20).join("\n  "))
            .unwrap_or_else(|| "<unknown>".to_owned())
    );
    println!("Validity:");
    println!(
        "  Not Before: {} ({})",
        tbs.validity.not_before,
        util::duration_since_now_fmt(tbs.validity.not_before),
    );
    println!(
        "  Not After: {} ({})",
        tbs.validity.not_after,
        util::duration_since_now_fmt(tbs.validity.not_after),
    );

    // if let Some(name_constraints) = anchor.name_constraints {
    //     println!("Name Constraints: {:?}", name_constraints);
    // }

    println!("Subject Public Key Info:");

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

            println!("  Algorithm: {ec_type} ({ec_subtype})");
            println!("  Public Key:\n    {public_key}");
        }

        _ if alg.oid == RSA_ENCRYPTION => {
            let algorithm = util::oid_desc_or_raw(&alg.oid);
            println!("  Algorithm: {algorithm}");

            let rsa_details =
                pkcs1::RsaPublicKey::from_der(spki.subject_public_key.as_bytes().unwrap()).unwrap();

            println!("  RSA:");

            let exp_bytes = rsa_details.public_exponent.as_bytes();
            let exp = BigEndian::read_uint(exp_bytes, exp_bytes.len());
            println!("    Exponent: {exp} (0x{exp:0x})");
            let mod_bytes = rsa_details.modulus.as_bytes();
            println!(
                "    Modulus({} bit):\n      {}",
                mod_bytes.len() * 8,
                util::openssl_hex(mod_bytes, 32).join("\n      ")
            );
        }

        _ => {
            let alg = util::oid_desc_or_raw(&alg.oid);
            println!("  Algorithm: {alg}");
        }
    }

    if let Some(extensions) = &tbs.extensions {
        println!("Extensions:");

        for ext in extensions {
            println!(
                "  ID: {}{}",
                util::oid_desc_or_raw(&ext.extn_id),
                if ext.critical { " (critical)" } else { "" }
            );
            println!("  Extension value:\n    {}", ext::interpret_val(ext));
            println!();
        }
    }

    println!("Signature:");
    println!(
        "  {}",
        util::openssl_hex(cert.signature.as_bytes().unwrap(), 20).join("\n  ")
    );
}
