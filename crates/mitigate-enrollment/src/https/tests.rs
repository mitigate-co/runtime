use super::*;
use crate::tls_fixture::{Fixture, response};
use crate::{EnrollmentCode, EnrollmentIdentity, EnrollmentKey};
use mitigate_secrets::Secret;
use std::{io, net::TcpListener, sync::mpsc, thread, time::Duration};
use ureq::tls::RootCerts;

const RECEIPT: &str = r#"{"schema_version":1,"enrollment":{"runtime_ref":"ref_11111111111111111111111111111111","enrollment_ref":"ref_22222222222222222222222222222222","enrolled_at_ms":1790614800000,"status":"active"}}"#;

impl Fixture {
    fn claim(&self) -> EnrollmentClaim {
        let code = EnrollmentCode::from_secret(
            Secret::from_bytes(
                format!(
                    "mcp1:00000000-0000-4000-8000-000000000001:{}",
                    "A".repeat(43)
                )
                .into_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        let identity = EnrollmentIdentity::from_references(
            serde_json::from_str("\"ref_11111111111111111111111111111111\"").unwrap(),
            serde_json::from_str("\"ref_22222222222222222222222222222222\"").unwrap(),
        )
        .unwrap();
        EnrollmentKey::generate()
            .unwrap()
            .claim(&self.origin, &code, &identity)
            .unwrap()
    }
}

#[track_caller]
fn run_failure(bytes: Vec<u8>, expected: Error) {
    let fixture = Fixture::start(bytes);
    assert_eq!(
        exchange(&fixture.agent, &fixture.claim()).err(),
        Some(expected)
    );
    // Early header rejection may close the socket before the fixture finishes.
    let _ = fixture.finish();
}

#[test]
fn verified_tls_sends_only_the_exact_signed_bootstrap_and_returns_bound_receipt() {
    let fixture = Fixture::start(response(200, "", RECEIPT));
    let claim = fixture.claim();
    let receipt = exchange(&fixture.agent, &claim).unwrap();
    assert_eq!(receipt.as_bytes(), RECEIPT.as_bytes());
    assert_eq!(receipt.receipt().enrolled_at_ms(), 1790614800000);
    let request = fixture.finish().unwrap();
    let header_end = request.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
    let headers = std::str::from_utf8(&request[..header_end])
        .unwrap()
        .to_ascii_lowercase();
    assert!(headers.starts_with("post /api/v1/runtime/enroll http/1.1\r\n"));
    assert!(headers.contains("content-type: application/json\r\n"));
    assert!(headers.contains("accept-encoding: identity\r\n"));
    for forbidden in [
        "cookie:",
        "authorization:",
        "origin:",
        "user-agent:",
        "referer:",
        "sec-fetch",
        "proxy-authorization:",
    ] {
        assert!(!headers.contains(forbidden));
    }
    assert_eq!(&request[header_end..], claim.as_bytes());
}

#[test]
fn untrusted_wrong_hostname_and_expired_certificates_send_no_http_claim() {
    let fixture = Fixture::start(response(200, "", RECEIPT));
    assert_eq!(submit(&fixture.claim()).err(), Some(Error::Connection));
    assert!(fixture.finish().is_err());
    for (name, expired) in [("elsewhere.example", false), ("127.0.0.1", true)] {
        let fixture = Fixture::custom(response(200, "", RECEIPT), name, expired, None);
        assert_eq!(
            exchange(&fixture.agent, &fixture.claim()).err(),
            Some(Error::Connection)
        );
        assert!(fixture.finish().is_err());
    }
}

#[test]
fn redirects_never_deliver_a_request_to_the_other_destination() {
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    other.set_nonblocking(true).unwrap();
    let location = format!(
        "Location: http://127.0.0.1:{}/canary\r\n",
        other.local_addr().unwrap().port()
    );
    for status in [301, 302, 303, 307, 308] {
        run_failure(
            response(status, &location, "provider-secret-canary"),
            Error::Redirect,
        );
        assert_eq!(
            other.accept().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn server_failures_have_fixed_categories_and_never_read_or_echo_error_bodies() {
    for (status, error) in [
        (400, Error::Rejected),
        (401, Error::Rejected),
        (403, Error::Rejected),
        (404, Error::Rejected),
        (409, Error::Rejected),
        (429, Error::RateLimited),
        (500, Error::Unavailable),
        (503, Error::Unavailable),
        (201, Error::Response),
        (204, Error::Response),
        (418, Error::Response),
    ] {
        run_failure(
            response(
                status,
                "Retry-After: secret-canary\r\n",
                "provider-secret-canary",
            ),
            error,
        );
        assert!(!format!("{error:?} {error} {}", error.code()).contains("canary"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn success_requires_closed_json_single_media_type_and_no_cookie_or_encoding() {
    for extra in [
        "Set-Cookie: secret-canary\r\n",
        "Content-Encoding: gzip\r\n",
        "Content-Encoding: identity\r\n",
        "Content-Type: application/json\r\n",
    ] {
        run_failure(response(200, extra, RECEIPT), Error::Response);
    }
    for body in [
        "provider-secret-canary".to_owned(),
        RECEIPT.replace("ref_1111", "ref_3333"),
        RECEIPT.replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"token\":\"secret-canary\"",
        ),
    ] {
        run_failure(response(200, "", &body), Error::Response);
    }
    for kind in ["text/html", "application/json; charset=latin1", ""] {
        let reply = String::from_utf8(response(200, "", RECEIPT))
            .unwrap()
            .replace(
                "Content-Type: application/json",
                &format!("Content-Type: {kind}"),
            );
        run_failure(reply.into_bytes(), Error::Response);
    }
}

#[test]
fn body_limits_apply_to_length_chunked_and_eof_delimited_responses() {
    let oversized = format!("{RECEIPT}{}", " ".repeat(MAX_ENROLLMENT_BYTES));
    run_failure(response(200, "", &oversized), Error::Response);
    run_failure(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{oversized}\r\n0\r\n\r\n", oversized.len()).into_bytes(), Error::Response);
    run_failure(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{oversized}").into_bytes(), Error::Response);
    run_failure(
        response(
            200,
            &format!("X-Oversized: {}\r\n", "x".repeat(9000)),
            RECEIPT,
        ),
        Error::Response,
    );
    let fixture = Fixture::start(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{RECEIPT}\r\n0\r\n\r\n", RECEIPT.len()).into_bytes());
    assert!(exchange(&fixture.agent, &fixture.claim()).is_ok());
    fixture.finish().unwrap();

    // A valid prefix is not a receipt when the declared body was truncated.
    run_failure(
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{RECEIPT}", RECEIPT.len() + 1).into_bytes(),
        Error::Connection,
    );
}

#[test]
fn inherited_proxy_settings_cannot_intercept_enrollment() {
    // Environment mutation is confined to a child process, not concurrent tests.
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let destination = format!("http://127.0.0.1:{}", proxy.local_addr().unwrap().port());
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "https::tests::verified_tls_sends_only_the_exact_signed_bootstrap_and_returns_bound_receipt"])
        .env("HTTP_PROXY", &destination)
        .env("HTTPS_PROXY", &destination)
        .env("ALL_PROXY", &destination)
        .env("http_proxy", &destination)
        .env("https_proxy", &destination)
        .env("all_proxy", &destination)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output().unwrap();
    assert!(
        output.status.success(),
        "TLS fixture must bypass inherited proxies"
    );
    assert_eq!(
        proxy.accept().err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn stalled_headers_and_streamed_body_have_deadlines_without_automatic_retry() {
    for reply in [
        vec![],
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999\r\n\r\n{"
            .to_vec(),
    ] {
        let (arrived_tx, arrived_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let fixture = Fixture::custom(reply, "127.0.0.1", false, Some((arrived_tx, resume_rx)));
        let claim = fixture.claim();
        let agent: Agent = config()
            .tls_config(fixture.agent.config().tls_config().clone())
            .timeout_global(Some(Duration::from_secs(2)))
            .timeout_recv_response(Some(Duration::from_millis(500)))
            .timeout_recv_body(Some(Duration::from_millis(500)))
            .build()
            .into();
        let client = thread::spawn(move || exchange(&agent, &claim).err());
        arrived_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(client.join().unwrap(), Some(Error::Timeout));
        resume_tx.send(()).unwrap();
        fixture.finish().unwrap();
    }
}

#[test]
fn transport_policy_disables_ambient_authority_and_dependency_logging() {
    let policy = config().build();
    assert!(policy.https_only());
    assert!(policy.proxy().is_none());
    assert_eq!(policy.max_redirects(), 0);
    assert_eq!(policy.max_idle_connections(), 0);
    assert!(!policy.tls_config().disable_verification());
    assert!(matches!(
        policy.tls_config().root_certs(),
        RootCerts::WebPki
    ));
    assert_eq!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off);
}
