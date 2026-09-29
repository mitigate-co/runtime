use super::*;
use crate::{
    EnrollmentIdentity, EnrollmentKey, PlatformOrigin,
    tls_fixture::{Fixture, response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mitigate_egress::{
    CheckedEvent, SyncRef,
    outbox::{Action, Admission, Limits, Outbox, Partition},
};
use mitigate_secrets::Secret;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    net::TcpListener,
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct EventFixture {
    signed: SignedEvent,
    outbox: Outbox,
    _directory: Directory,
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn event_bytes() -> &'static [u8] {
    include_bytes!("../../../../examples/egress/decision.json")
}
fn event_fixture(origin: &PlatformOrigin) -> EventFixture {
    event_fixture_for(origin, event_bytes())
}
fn event_fixture_for(origin: &PlatformOrigin, input: &[u8]) -> EventFixture {
    let dir = std::env::temp_dir().join(format!(
        "mitigate-event-https-{}",
        SyncRef::fresh().unwrap().as_str()
    ));
    fs::create_dir(&dir).unwrap();
    let directory = Directory(dir);
    let identity = EnrollmentIdentity::from_references(
        serde_json::from_value(json!("ref_22222222222222222222222222222222")).unwrap(),
        serde_json::from_value(json!("ref_99999999999999999999999999999999")).unwrap(),
    )
    .unwrap();
    let mut outbox = Outbox::create(
        &directory.0.join("outbox.sqlite"),
        Partition {
            runtime_ref: identity.runtime_ref().clone(),
            enrollment_ref: identity.enrollment_ref().clone(),
        },
        Limits::default(),
    )
    .unwrap();
    assert_eq!(outbox.admit(input), Ok(Admission::Queued));
    let lease = outbox.claim().unwrap().unwrap();
    let key = EnrollmentKey::from_secret(
        Secret::from_bytes(URL_SAFE_NO_PAD.encode([23; 32]).into_bytes()).unwrap(),
    )
    .unwrap();
    EventFixture {
        signed: key.sign_event(origin, &identity, &lease).unwrap(),
        outbox,
        _directory: directory,
    }
}
fn receipt() -> String {
    receipt_for(event_bytes())
}
fn receipt_for(input: &[u8]) -> String {
    let event = CheckedEvent::from_bytes(input).unwrap();
    json!({
        "schema_version":1, "event_id":event.event_id(), "runtime_ref":event.runtime_ref(),
        "enrollment_ref":"ref_99999999999999999999999999999999",
        "event_digest":URL_SAFE_NO_PAD.encode(Sha256::digest(event.as_bytes())),
        "status":"accepted"
    })
    .to_string()
}

#[test]
fn inventory_https_requires_its_own_digest_and_classifies_unsupported_receivers() {
    let input = include_bytes!("../../../../examples/egress/inventory-part.json");
    for (status, body, expected, pending) in [
        (200, receipt_for(input), Delivery::Accepted, 0),
        (200, receipt(), Delivery::Retry(Error::Response), 1),
        (
            422,
            "synthetic-private-refusal".to_owned(),
            Delivery::Rejected,
            0,
        ),
    ] {
        let tls = Fixture::start(response(status, "", &body));
        let mut fixture = event_fixture_for(&tls.origin, input);
        fixture.outbox.purge().unwrap();
        fixture.outbox.set_paused(false).unwrap();
        assert_eq!(fixture.outbox.admit(input), Ok(Admission::Queued));
        assert_eq!(
            deliver_with(&mut fixture.outbox, |outbox, lease| {
                checked_exchange(outbox, lease, &fixture.signed, &tls.agent)
            }),
            Ok(expected)
        );
        let report = fixture.outbox.inspect().unwrap();
        assert_eq!(report.pending, pending);
        assert_eq!(report.receipts, usize::from(pending == 0));
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("synthetic-private")
        );
        assert!(tls.finish().unwrap().ends_with(fixture.signed.as_bytes()));
    }
}

fn ready_fixture(origin: &PlatformOrigin) -> EventFixture {
    let mut fixture = event_fixture(origin);
    // Discard the setup lease. The runner must obtain its own committed claim.
    fixture.outbox.purge().unwrap();
    fixture.outbox.set_paused(false).unwrap();
    assert_eq!(fixture.outbox.admit(event_bytes()), Ok(Admission::Queued));
    fixture
}

// Failure-only synthetic diagnostics for #50. Never add an inspection/write
// between claiming and checking readiness: it would change the measured path.
fn observed_delivery(
    outbox: &mut Outbox,
    signed: &SignedEvent,
    agent: &Agent,
) -> Result<Delivery, Error> {
    let started = Instant::now();
    let wall_start = wall_millis();
    let mut claim_elapsed = None;
    let mut check_elapsed = None;
    let mut check_wall = None;
    let result = deliver_with(outbox, |outbox, lease| {
        claim_elapsed = Some(started.elapsed().as_millis());
        check_wall = wall_millis();
        let checking = Instant::now();
        let result = checked_exchange(outbox, lease, signed, agent);
        check_elapsed = Some(checking.elapsed().as_millis());
        result
    });
    let elapsed = started.elapsed().as_millis();
    let wall_end = wall_millis();
    if result.is_err() {
        let report = outbox.inspect().ok();
        let claimed = report.as_ref().and_then(|report| {
            report
                .recent
                .iter()
                .rev()
                .find(|entry| entry.action == Action::Claimed)
        });
        let claim_age = check_wall
            .zip(claimed)
            .map(|(now, entry)| now - i128::from(entry.time_ms));
        let wall_elapsed = wall_end.zip(wall_start).map(|(end, start)| end - start);
        eprintln!(
            "synthetic delivery: result={result:?} elapsed_ms={elapsed} \
             claim_return_ms={claim_elapsed:?} check_ms={check_elapsed:?} \
             wall_elapsed_ms={wall_elapsed:?} claim_age_at_check_ms={claim_age:?} \
             paused={:?} pending={:?} leased={:?}",
            report.as_ref().map(|report| report.paused),
            report.as_ref().map(|report| report.pending),
            report.as_ref().map(|report| report.leased),
        );
    }
    result
}

fn wall_millis() -> Option<i128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| time.as_millis().try_into().ok())
}

#[test]
fn composed_delivery_commits_only_the_exact_authenticated_receipt() {
    let tls = Fixture::start(response(200, "", &receipt()));
    let mut fixture = ready_fixture(&tls.origin);
    assert_eq!(
        deliver_with(&mut fixture.outbox, |outbox, lease| {
            checked_exchange(outbox, lease, &fixture.signed, &tls.agent)
        }),
        Ok(Delivery::Accepted)
    );
    let report = fixture.outbox.inspect().unwrap();
    assert_eq!((report.pending, report.leased, report.receipts), (0, 0, 1));
    assert_eq!(
        fixture.outbox.admit(event_bytes()),
        Ok(Admission::Duplicate)
    );
    let request = tls.finish().unwrap();
    assert!(request.ends_with(fixture.signed.as_bytes()));
}

#[test]
fn composed_delivery_retains_uncertain_events_and_pauses_refused_authority() {
    for (status, reason, expected) in [
        (
            401,
            Error::Unauthorized,
            Delivery::Paused(Error::Unauthorized),
        ),
        (302, Error::Redirect, Delivery::Paused(Error::Redirect)),
        (429, Error::RateLimited, Delivery::Retry(Error::RateLimited)),
        (503, Error::Unavailable, Delivery::Retry(Error::Unavailable)),
        (200, Error::Response, Delivery::Retry(Error::Response)),
    ] {
        let tls = Fixture::start(response(status, "", "private-response-canary"));
        let mut fixture = ready_fixture(&tls.origin);
        assert_eq!(
            observed_delivery(&mut fixture.outbox, &fixture.signed, &tls.agent),
            Ok(expected)
        );
        let report = fixture.outbox.inspect().unwrap();
        assert_eq!((report.pending, report.leased, report.receipts), (1, 0, 0));
        assert_eq!(
            report.paused,
            matches!(reason, Error::Unauthorized | Error::Redirect)
        );
        assert!(!serde_json::to_string(&report).unwrap().contains("canary"));
        let request = tls.finish().unwrap();
        assert!(request.ends_with(fixture.signed.as_bytes()));
    }
}

#[test]
fn composed_permanent_refusal_is_not_retried_and_idle_never_opens_transport() {
    let tls = Fixture::start(response(422, "", "private-response-canary"));
    let mut fixture = ready_fixture(&tls.origin);
    assert_eq!(
        deliver_with(&mut fixture.outbox, |outbox, lease| {
            checked_exchange(outbox, lease, &fixture.signed, &tls.agent)
        }),
        Ok(Delivery::Rejected)
    );
    assert_eq!(fixture.outbox.inspect().unwrap().pending, 0);
    assert_eq!(
        fixture.outbox.admit(event_bytes()),
        Ok(Admission::Duplicate)
    );
    assert_eq!(
        deliver_with(&mut fixture.outbox, |_, _| panic!("empty queue sent")),
        Ok(Delivery::Idle)
    );
    fixture.outbox.purge().unwrap();
    fixture.outbox.set_paused(false).unwrap();
    fixture.outbox.admit(event_bytes()).unwrap();
    fixture.outbox.set_paused(true).unwrap();
    assert_eq!(
        deliver_with(&mut fixture.outbox, |_, _| panic!("paused queue sent")),
        Ok(Delivery::Idle)
    );
    tls.finish().unwrap();
}

#[test]
fn consent_withdrawal_after_claim_prevents_network_and_cannot_be_overridden() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = PlatformOrigin::parse(&format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    ))
    .unwrap();
    for purge in [false, true] {
        let mut fixture = ready_fixture(&origin);
        let result = deliver_with(&mut fixture.outbox, |outbox, lease| {
            if purge {
                outbox.purge().unwrap();
            } else {
                outbox.set_paused(true).unwrap();
            }
            checked_exchange(
                outbox,
                lease,
                &fixture.signed,
                &transport::config().build().into(),
            )
        });
        assert_eq!(
            result,
            Err(if purge {
                Error::Outbox(outbox::Error::StaleLease)
            } else {
                Error::NotReady
            })
        );
        let report = fixture.outbox.inspect().unwrap();
        assert!(report.paused);
        assert_eq!(report.pending, usize::from(!purge));
        assert_eq!(
            listener.accept().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn acceptance_cannot_be_reported_after_local_completion_loses_ownership() {
    let tls = Fixture::start(response(200, "", &receipt()));
    let mut fixture = ready_fixture(&tls.origin);
    assert_eq!(
        deliver_with(&mut fixture.outbox, |outbox, lease| {
            let accepted = checked_exchange(outbox, lease, &fixture.signed, &tls.agent)?;
            // A concurrent opt-out can purge after the server accepted bytes.
            // Its local state wins; the response cannot recreate/acknowledge it.
            outbox.purge().unwrap();
            Ok(accepted)
        }),
        Err(Error::Outbox(outbox::Error::StaleLease))
    );
    let report = fixture.outbox.inspect().unwrap();
    assert!(report.paused);
    assert_eq!((report.pending, report.receipts), (0, 0));
    tls.finish().unwrap();
}

#[test]
fn local_failures_preserve_claims_and_transport_failures_schedule_recovery() {
    let origin = PlatformOrigin::parse("https://mitigate.example").unwrap();
    for reason in [
        Error::Connection,
        Error::Timeout,
        Error::Enrollment(storage::Error::Scope),
        Error::Outbox(outbox::Error::Busy),
        Error::NotReady,
    ] {
        let mut fixture = ready_fixture(&origin);
        let result = deliver_with(&mut fixture.outbox, |_, _| Err(reason));
        let retry = matches!(reason, Error::Connection | Error::Timeout);
        assert_eq!(
            result,
            if retry {
                Ok(Delivery::Retry(reason))
            } else {
                Err(reason)
            }
        );
        let report = fixture.outbox.inspect().unwrap();
        assert_eq!(report.pending, 1);
        assert_eq!(report.leased, usize::from(!retry));
        assert!(!report.paused);
    }
}
#[track_caller]
fn rejected(reply: Vec<u8>, expected: Error) {
    let fixture = Fixture::start(reply);
    let mut event = event_fixture(&fixture.origin);
    assert_eq!(
        exchange(&fixture.agent, &event.signed).err(),
        Some(expected)
    );
    assert_eq!(event.outbox.inspect().unwrap().pending, 1);
    let _ = fixture.finish();
}

#[test]
fn verified_event_delivery_sends_exact_checked_body_without_mutating_the_queue() {
    let fixture = Fixture::start(response(200, "", &receipt()));
    let mut event = event_fixture(&fixture.origin);
    let accepted = exchange(&fixture.agent, &event.signed).unwrap();
    assert_eq!(
        accepted.receipt().event_id().as_str(),
        "ref_11111111111111111111111111111111"
    );
    assert_eq!(event.outbox.inspect().unwrap().pending, 1);
    let request = fixture.finish().unwrap();
    let end = request.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
    let headers = std::str::from_utf8(&request[..end])
        .unwrap()
        .to_ascii_lowercase();
    assert!(headers.starts_with("post /api/v1/runtime/events http/1.1\r\n"));
    assert!(headers.contains("content-type: application/json\r\n"));
    assert!(headers.contains("cache-control: no-store\r\n"));
    assert!(headers.contains("accept-encoding: identity\r\n"));
    for name in [
        "authorization:",
        "cookie:",
        "origin:",
        "user-agent:",
        "referer:",
        "sec-fetch",
        "proxy-authorization:",
    ] {
        assert!(!headers.contains(name));
    }
    assert_eq!(&request[end..], event.signed.as_bytes());
    let body: Value = serde_json::from_slice(&request[end..]).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 4);
    assert!(!String::from_utf8(request).unwrap().contains("mcp1:"));
}

#[test]
fn invalid_certificates_never_receive_http_event_bytes() {
    let fixture = Fixture::start(response(200, "", &receipt()));
    let event = event_fixture(&fixture.origin);
    assert_eq!(
        exchange(&transport::config().build().into(), &event.signed).err(),
        Some(Error::Connection)
    );
    assert!(fixture.finish().is_err());
    for (name, expired) in [("elsewhere.example", false), ("127.0.0.1", true)] {
        let fixture = Fixture::custom(response(200, "", &receipt()), name, expired, None);
        let event = event_fixture(&fixture.origin);
        assert_eq!(
            exchange(&fixture.agent, &event.signed).err(),
            Some(Error::Connection)
        );
        assert!(fixture.finish().is_err());
    }
}

#[test]
fn redirects_and_error_responses_never_supply_retry_content_or_diagnostics() {
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    other.set_nonblocking(true).unwrap();
    let extra = format!(
        "Location: http://127.0.0.1:{}/secret-canary\r\nRetry-After: secret-canary\r\n",
        other.local_addr().unwrap().port()
    );
    for (status, expected) in [
        (301, Error::Redirect),
        (302, Error::Redirect),
        (303, Error::Redirect),
        (307, Error::Redirect),
        (308, Error::Redirect),
        (400, Error::Rejected),
        (409, Error::Rejected),
        (413, Error::Rejected),
        (422, Error::Rejected),
        (401, Error::Unauthorized),
        (403, Error::Unauthorized),
        (404, Error::Unauthorized),
        (410, Error::Unauthorized),
        (429, Error::RateLimited),
        (500, Error::Unavailable),
        (503, Error::Unavailable),
        (201, Error::Response),
        (204, Error::Response),
        (418, Error::Response),
    ] {
        // A success-sized body limit is deliberately exceeded: status handling
        // must happen before reading/parsing any rejected provider response.
        rejected(
            response(status, &extra, &"secret-canary".repeat(200)),
            expected,
        );
        assert!(!format!("{expected:?} {expected} {}", expected.code()).contains("canary"));
        assert!(std::error::Error::source(&expected).is_none());
    }
    assert_eq!(
        other.accept().err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn success_requires_bounded_json_and_exact_event_acknowledgment() {
    let accepted = receipt();
    for extra in [
        "Set-Cookie: secret-canary\r\n",
        "Content-Encoding: gzip\r\n",
        "Content-Encoding: identity\r\n",
        "Content-Type: application/json\r\n",
    ] {
        rejected(response(200, extra, &accepted), Error::Response);
    }
    for body in [
        "secret-canary".to_owned(),
        accepted.replace("ref_1111", "ref_3333"),
        accepted.replacen('{', "{\"schema_version\":1,", 1),
        accepted.replacen('{', "{\"metadata\":\"secret-canary\",", 1),
    ] {
        rejected(response(200, "", &body), Error::Response);
    }
    for kind in ["text/html", "application/json; charset=latin1", ""] {
        let reply = String::from_utf8(response(200, "", &accepted))
            .unwrap()
            .replace(
                "Content-Type: application/json",
                &format!("Content-Type: {kind}"),
            );
        rejected(reply.into_bytes(), Error::Response);
    }
    let oversized = format!("{accepted}{}", " ".repeat(MAX_EVENT_RECEIPT_BYTES));
    rejected(response(200, "", &oversized), Error::Response);
    rejected(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{oversized}\r\n0\r\n\r\n",oversized.len()).into_bytes(),Error::Response);
    rejected(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{oversized}").into_bytes(),Error::Response);
    rejected(
        response(
            200,
            &format!("X-Large: {}\r\n", "x".repeat(9000)),
            &accepted,
        ),
        Error::Response,
    );
    rejected(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{accepted}",accepted.len()+1).into_bytes(),Error::Connection);
    let fixture = Fixture::start(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{accepted}\r\n0\r\n\r\n",accepted.len()).into_bytes());
    assert!(exchange(&fixture.agent, &event_fixture(&fixture.origin).signed).is_ok());
    fixture.finish().unwrap();
}

#[test]
fn inherited_proxies_cannot_receive_event_delivery() {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let destination = format!("http://127.0.0.1:{}", proxy.local_addr().unwrap().port());
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact","event_https::tests::verified_event_delivery_sends_exact_checked_body_without_mutating_the_queue"]);
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(variable, &destination);
    }
    let output = command
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Event TLS fixture must bypass inherited proxies"
    );
    assert_eq!(
        proxy.accept().err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn stalled_event_responses_have_deadlines_and_keep_the_queued_event() {
    for reply in [
        vec![],
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999\r\n\r\n{"
            .to_vec(),
    ] {
        let (arrived_tx, arrived_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let fixture = Fixture::custom(reply, "127.0.0.1", false, Some((arrived_tx, resume_rx)));
        let mut event = event_fixture(&fixture.origin);
        let agent: Agent = transport::config()
            .tls_config(fixture.agent.config().tls_config().clone())
            .timeout_global(Some(Duration::from_secs(2)))
            .timeout_recv_response(Some(Duration::from_millis(500)))
            .timeout_recv_body(Some(Duration::from_millis(500)))
            .build()
            .into();
        let client = thread::spawn(move || {
            let result = exchange(&agent, &event.signed).err();
            assert_eq!(event.outbox.inspect().unwrap().pending, 1);
            result
        });
        arrived_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(client.join().unwrap(), Some(Error::Timeout));
        resume_tx.send(()).unwrap();
        fixture.finish().unwrap();
    }
}
