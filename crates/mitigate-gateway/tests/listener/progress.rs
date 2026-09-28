use super::*;

#[tokio::test(start_paused = true)]
async fn progress_uses_only_the_current_clients_token_and_bounded_counters() {
    let (server, client) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(server);
    let mut client = BufReader::new(client);
    let mut service = Service {
        progress: true,
        ..Service::default()
    };
    let (outcome, ()) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending()
        ),
        async {
            initialize(&mut client, "2025-11-25").await;
            for (id, token) in [(2, json!("client-token")), (3, json!(42))] {
                send(
                    &mut client,
                    request(
                        json!(id),
                        "tools/call",
                        json!({"name":"read_status",
                "_meta":{"progressToken":token,"message":"must-not-forward"}}),
                    ),
                )
                .await;
                let mut updates = 0;
                loop {
                    let message = receive(&mut client).await;
                    if message.get("result").is_some() {
                        assert_eq!(message["id"], id);
                        break;
                    }
                    assert_eq!(message["method"], "notifications/progress");
                    assert_eq!(message["params"]["progressToken"], token);
                    assert_eq!(message["params"].as_object().unwrap().len(), 3);
                    assert_eq!(message["params"]["total"], 2.0);
                    updates += 1;
                }
                assert!(updates >= 1);
            }
            client.shutdown().await.unwrap();
        }
    );
    assert_eq!(outcome, Ok(()));
}

#[tokio::test(start_paused = true)]
async fn operator_request_budget_is_enforced_and_out_of_range_budgets_are_rejected() {
    use std::time::Duration;
    for millis in [0, 99, 300_001] {
        let (server, _client) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let mut service = Service {
            budget: Some(Duration::from_millis(millis)),
            ..Service::default()
        };
        assert_eq!(
            serve(
                BufReader::new(read),
                write,
                &mut service,
                CallerIdentity::default(),
                std::future::pending()
            )
            .await,
            Err(Error::Limit)
        );
    }
    let (server, client) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(server);
    let mut client = BufReader::new(client);
    let mut service = Service {
        pending: true,
        budget: Some(Duration::from_millis(100)),
        ..Service::default()
    };
    let (outcome, ()) = tokio::join!(
        serve(
            BufReader::new(read),
            write,
            &mut service,
            CallerIdentity::default(),
            std::future::pending()
        ),
        async {
            initialize(&mut client, "2025-11-25").await;
            let start = tokio::time::Instant::now();
            send(&mut client, request(json!(2), "tools/list", json!({}))).await;
            assert_eq!(receive(&mut client).await["error"]["code"], -32002);
            assert_eq!(start.elapsed(), Duration::from_millis(100));
        }
    );
    assert_eq!(outcome, Err(Error::Timeout));
    assert!(service.dropped.get());
}
