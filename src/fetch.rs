use std::{
    io::{self, Read, Write as _},
    net::TcpStream,
    sync::Arc,
};

use der::Decode;
use rustls::{
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

    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(host).unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let sock = TcpStream::connect(format!("{host}:443")).unwrap();
    let mut sock = TlsInspector::new(sock);
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(
        format!(
            r#"
GET / HTTP/1.1\r
Host: {host}\r
Connection: close\r
Accept-Encoding: identity\r

"#
        )
        .replace('\n', "\r\n")
        .as_bytes(),
    )
    .unwrap();

    tls.flush().unwrap();

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();

    tls.sock
        .take_certificates()
        .map(|der_certs| {
            der_certs
                .into_iter()
                .filter_map(|der| Certificate::from_der(&der.0).ok())
                .collect()
        })
        .unwrap_or_default()
}

struct TlsInspector {
    inner: TcpStream,
    buf: Vec<u8>,

    certificates: Option<CertificatePayload>,
}

impl TlsInspector {
    fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            certificates: None,
        }
    }

    fn take_certificates(&mut self) -> Option<CertificatePayload> {
        self.buf = Vec::new();
        self.certificates.take()
    }
}

impl io::Read for TlsInspector {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let res = self.inner.read(buf);

        if self.certificates.is_none() {
            self.buf.extend(&*buf);
            self.certificates = parse_certs(&self.buf);
        }

        res
    }
}

impl io::Write for TlsInspector {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn parse_certs(data: &[u8]) -> Option<CertificatePayload> {
    let mut reader = Reader::init(data);

    while let Ok(msg) = OpaqueMessage::read(&mut reader) {
        let msg = Message::try_from(msg.into_plain_message()).ok()?;

        if let MessagePayload::Handshake {
            parsed:
                HandshakeMessagePayload {
                    payload: HandshakePayload::Certificate(mut certs),
                    ..
                },
            ..
        } = msg.payload
        {
            certs.retain(|cert| !cert.0.is_empty());
            return Some(certs);
        }
    }

    None
}
