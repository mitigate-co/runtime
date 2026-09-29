//! In-memory synthetic loopback TLS fixture shared by both fixed HTTP protocols.
use crate::{PlatformOrigin, transport::config};
use rcgen::{CertificateParams, KeyPair};
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use ureq::{
    Agent,
    tls::{Certificate, RootCerts, TlsConfig},
};

pub(crate) struct Fixture {
    pub(crate) origin: PlatformOrigin,
    pub(crate) agent: Agent,
    server: JoinHandle<io::Result<Vec<u8>>>,
}
impl Fixture {
    pub(crate) fn start(response: Vec<u8>) -> Self {
        Self::custom(response, "127.0.0.1", false, None)
    }
    pub(crate) fn custom(
        response: Vec<u8>,
        cert_name: &str,
        expired: bool,
        pause: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    ) -> Self {
        // All keys/certificates are generated in memory for this one loopback
        // listener; none is a checked-in key, installed root or trust bypass.
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![cert_name.to_owned()]).unwrap();
        if expired {
            params.not_before = rcgen::date_time_ymd(2010, 1, 1);
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        }
        let cert = params.self_signed(&key).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::new_with_certs(&[Certificate::from_der(
                cert.der(),
            )
            .to_owned()]))
            .build();
        let agent = config().tls_config(tls).build().into();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = PlatformOrigin::parse(&format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => return Err(e),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            stream.set_write_timeout(Some(Duration::from_secs(3)))?;
            let session = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(session, stream);
            let request = read_request(&mut stream)?;
            stream.write_all(&response)?;
            stream.flush()?;
            if let Some((arrived, resume)) = pause {
                arrived.send(()).unwrap();
                resume.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            // Send TLS close_notify so an EOF-delimited response is authenticated.
            stream.conn.send_close_notify();
            let _ = stream.flush();
            Ok(request)
        });
        Self {
            origin,
            agent,
            server,
        }
    }
    pub(crate) fn finish(self) -> io::Result<Vec<u8>> {
        self.server.join().expect("fixture server did not panic")
    }
}

fn read_request(stream: &mut StreamOwned<ServerConnection, TcpStream>) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break bytes.len();
        }
        if bytes.len() > 8192 {
            return Err(io::Error::other("fixture request headers oversized"));
        }
    };
    let headers = String::from_utf8(bytes.clone())
        .unwrap()
        .to_ascii_lowercase();
    let length = headers
        .lines()
        .find_map(|l| l.strip_prefix("content-length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!(length <= crate::event::MAX_SIGNED_EVENT_BYTES);
    bytes.resize(header_end + length, 0);
    stream.read_exact(&mut bytes[header_end..])?;
    Ok(bytes)
}
pub(crate) fn response(status: u16, extra: &str, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len()).into_bytes()
}
