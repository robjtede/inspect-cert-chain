use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::Arc,
};

use der::Decode;
use error_reporter::Report;
use eyre::WrapErr;
use rustls::{client::ServerCertVerifier, OwnedTrustAnchor, RootCertStore, ServerName};
use x509_cert::Certificate;

pub(crate) fn cert_chain(host: &str) -> eyre::Result<Vec<Certificate>> {
    let server_name = ServerName::try_from(host)
        .with_context(|| format!("failed to convert given host (\"{host}\") to server name"))?;

    let mut root_store = RootCertStore::empty();

    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS12])?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoopServerCertVerifier));

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect(format!("{host}:443"))
        .wrap_err_with(|| format!("failed to connect to host: {host}:443"))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let req = format!(
        r#"GET / HTTP/1.1
Host: {host}
Connection: close
User-Agent: inspect-cert-chain/{}
Accept-Encoding: identity

"#,
        env!("CARGO_PKG_VERSION"),
    )
    .replace('\n', "\r\n");

    tracing::debug!("writing to socket:\n{req}");

    tls.write_all(req.as_bytes())
        .wrap_err("failed to write to socket")?;
    tls.flush().wrap_err("failed to flush socket")?;

    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
        Ok(_) => {}
        Err(err) => {
            tracing::warn!("failed to read from {host}: {}", Report::new(err));
        }
    }

    // peer_certificates method will return certificates by now
    // because app data has already been written
    Ok(tls
        .conn
        .peer_certificates()
        .map(|c| {
            c.iter()
                .filter_map(|c| Certificate::from_der(&c.0).ok())
                .collect()
        })
        .unwrap_or_default())
}

struct NoopServerCertVerifier;

impl ServerCertVerifier for NoopServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
