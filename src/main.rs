#![allow(unused)]
#![deny(rust_2018_idioms, future_incompatible)]

use std::fs;

use byteorder::{BigEndian, ByteOrder as _};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION};
use const_oid::{db::DB, ObjectIdentifier};
use der::{Decode as _, DecodePem};
use itertools::Itertools as _;
use memchr::memmem;
use x509_cert::Certificate;

use crate::util::{assert_null_params, openssl_hex};

mod ext;
mod fetch;
mod util;

// let anchor = &TLS_SERVER_ROOTS.0[3]; // seems to have wrong modulus ?!?

fn main() {
    let host = std::env::args().nth(1).unwrap();

    let certs = fetch::cert_chain(&host);

    for cert in certs.into_iter().take(1) {
        print_cert_info(&cert);

        println!();
        println!();
    }
}

fn print_cert_info(cert: &Certificate) {
    println!("Certificate");
    println!("===========");

    let tbs = &cert.tbs_certificate;

    let tbs_cert = &tbs;
    println!("Subject: {}", tbs_cert.subject);

    println!("Issuer: {}", tbs.issuer);

    println!("Version: {:?}", tbs.version);
    println!(
        "Serial Number:\n  {}",
        tbs.subject_unique_id
            .as_ref()
            .map(|serial| openssl_hex(serial.as_bytes().unwrap(), 20).join("\n  "))
            .unwrap_or_else(|| "<unknown>".to_owned())
    );

    println!(
        "Signature Algorithm: {}",
        DB.by_oid(&cert.signature_algorithm.oid).unwrap()
    );
    assert_null_params(&cert.signature_algorithm);

    println!(
        "Issuer Serial Number:\n  {}",
        tbs.issuer_unique_id
            .as_ref()
            .map(|serial| openssl_hex(serial.as_bytes().unwrap(), 20).join("\n  "))
            .unwrap_or_else(|| "<unknown>".to_owned())
    );
    println!("Validity:");
    println!(
        "  Not Before: {} ({})",
        tbs.validity.not_before,
        duration_since_now_fmt(tbs.validity.not_before),
    );
    println!(
        "  Not After: {} ({})",
        tbs.validity.not_after,
        duration_since_now_fmt(tbs.validity.not_after),
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

            let ec_type = DB.by_oid(&alg.oid).unwrap();
            let ec_subtype = DB.by_oid(&ec_subtype).unwrap();

            let public_key_bytes = spki.subject_public_key.as_bytes().unwrap();
            let public_key = util::openssl_hex(public_key_bytes, 15).join("\n    ");

            println!("  Algorithm: {ec_type} ({ec_subtype})");
            println!("  Public Key:\n    {public_key}");
        }

        _ if alg.oid == RSA_ENCRYPTION => {
            let algorithm = DB.by_oid(&alg.oid).unwrap().to_owned();
            println!("  Algorithm: {algorithm}");

            let rsa_details =
                pkcs1::RsaPublicKey::from_der(spki.subject_public_key.as_bytes().unwrap()).unwrap();

            println!("  RSA:");

            let exp_bytes = rsa_details.public_exponent.as_bytes();
            let exp = BigEndian::read_uint(exp_bytes, exp_bytes.len());
            println!("    Exponent: {exp} (0x{exp:0x})");
            println!(
                "    Modulus:\n      {}",
                util::openssl_hex(rsa_details.modulus.as_bytes(), 15).join("\n      ")
            );
        }

        _ => {
            let alg = DB.by_oid(&alg.oid).unwrap_or("unknown").to_owned();
            println!("  Algorithm: {alg}");
        }
    }

    if let Some(extensions) = &tbs.extensions {
        println!("Extensions:");

        for ext in extensions {
            println!(
                "  ID: {}{}",
                DB.by_oid(&ext.extn_id)
                    .map(ToOwned::to_owned)
                    .unwrap_or(ext.extn_id.to_string()),
                if ext.critical { " (critical)" } else { "" }
            );
            println!("  Extension value:\n    {}", ext::interpret_val(ext));
            println!();
        }
    }

    println!("Signature:");
    println!(
        "  {}",
        openssl_hex(cert.signature.as_bytes().unwrap(), 20).join("\n  ")
    );
}

fn duration_since_now_fmt(time: x509_cert::time::Time) -> String {
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

fn certs(chain: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    let needle = b"-----END CERTIFICATE-----";

    let mut start_idx = 0;

    std::iter::from_fn(move || {
        if chain[start_idx..] == [0x0d]
            || chain[start_idx..] == [0x0d, 0x0a]
            || chain[start_idx..].is_empty()
        {
            return None;
        }

        if let Some(idx) = memmem::find(&chain[start_idx..], needle) {
            let cert = &chain[start_idx..(start_idx + idx + 25)];
            start_idx += idx + 26;

            if chain[start_idx] == 0x0a {
                start_idx += 1;
            }

            Some(cert.to_owned())
        } else {
            let rest = &chain[start_idx..];
            start_idx += rest.len();
            Some(rest.to_owned())
        }
    })
}
