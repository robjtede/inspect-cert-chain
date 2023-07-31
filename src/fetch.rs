use std::{
    io::{self, Read, Write as _},
    net::TcpStream,
    sync::Arc,
};

use der::Decode;
use rustls::{
    client::ServerCertVerifier,
    internal::msgs::{
        codec::Reader,
        handshake::{CertificatePayload, HandshakeMessagePayload, HandshakePayload},
        message::{Message, MessagePayload, OpaqueMessage},
    },
    OwnedTrustAnchor, RootCertStore, ServerName,
};
use x509_cert::Certificate;

pub(crate) fn cert_chain(host: &str) -> Vec<Certificate> {
    let mut root_store = RootCertStore::empty();

    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoopServerCertVerifier));

    let server_name = ServerName::try_from(host).unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{host}:443")).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(
        format!(
            r#"GET / HTTP/1.1
Host: {host}
Connection: close
Accept-Encoding: identity

"#
        )
        .replace('\n', "\r\n")
        .as_bytes(),
    )
    .unwrap();

    tls.flush().unwrap();

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();

    // peer_certificates method will return certificates by now
    // because app data has already been written
    tls.conn
        .peer_certificates()
        .map(|c| {
            c.iter()
                .filter_map(|c| Certificate::from_der(&c.0).ok())
                .collect()
        })
        .unwrap_or_default()
}

struct NoopServerCertVerifier;

impl ServerCertVerifier for NoopServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
