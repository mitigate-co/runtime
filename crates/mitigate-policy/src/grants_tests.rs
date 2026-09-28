use super::*;
use serde_json::json;

fn context_value() -> Value {
    json!({"schema_version":1,"client":"1".repeat(64),"principal":"2".repeat(64),
        "agent":"3".repeat(64),"server":"4".repeat(64),"tool":"5".repeat(64),
        "capabilities":["read_data"],"environment":"development","time_ms":1000})
}
fn context(value: &Value) -> GrantContext {
    GrantContext::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn rule(effect: &str, id: char) -> Value {
    json!({"grant_ref":id.to_string().repeat(64),"effect":effect,"scope":{
        "client":null,"principal":null,"agent":null,"server":null,"tool":null,
        "capabilities":null,"environment":null,"not_before_ms":null,"expires_at_ms":null}})
}
fn parse(rules: &[Value]) -> Result<GrantSet, Error> {
    GrantSet::from_bytes(&serde_json::to_vec(&json!({"schema_version":1,"grants":rules})).unwrap())
}
fn evaluate(rules: &[Value], value: &Value) -> GrantResolution {
    parse(rules).unwrap().evaluate(&context(value)).unwrap()
}

#[test]
fn deny_wins_regardless_of_order_or_specificity() {
    let c = context_value();
    let mut narrow_allow = rule("allow", 'a');
    narrow_allow["scope"]["tool"] = c["tool"].clone();
    let broad_allow = rule("allow", 'b');
    let mut narrow_deny = rule("deny", 'c');
    narrow_deny["scope"]["agent"] = c["agent"].clone();
    let broad_deny = rule("deny", 'd');
    let mut rules = vec![narrow_allow, broad_allow, narrow_deny, broad_deny];
    let expected = evaluate(&rules, &c);
    assert_eq!(expected.state(), GrantState::Denied);
    assert_eq!(expected.reason(), Reason::ExplicitDeny);
    assert_eq!(
        serde_json::to_value(&expected).unwrap()["matched_grants"],
        json!(["c".repeat(64), "d".repeat(64)])
    );
    for _ in 0..rules.len() {
        rules.rotate_left(1);
        assert_eq!(evaluate(&rules, &c), expected);
    }
    rules.reverse();
    assert_eq!(evaluate(&rules, &c), expected);
}

#[test]
fn every_exact_scope_is_conjunctive_and_case_sensitive() {
    let c = context_value();
    let mut allowance = rule("allow", 'a');
    for field in [
        "client",
        "principal",
        "agent",
        "server",
        "tool",
        "environment",
    ] {
        allowance["scope"][field] = c[field].clone();
    }
    assert_eq!(
        evaluate(&[allowance.clone()], &c).state(),
        GrantState::Explicit
    );
    for field in [
        "client",
        "principal",
        "agent",
        "server",
        "tool",
        "environment",
    ] {
        let mut changed = c.clone();
        changed[field] = if field == "environment" {
            json!("Development")
        } else {
            json!("f".repeat(64))
        };
        assert_eq!(
            evaluate(&[allowance.clone()], &changed).state(),
            GrantState::None,
            "matched a different {field}"
        );
    }
}

#[test]
fn unknowns_are_never_invented_or_treated_as_exact_matches() {
    for field in ["principal", "agent", "environment"] {
        let mut c = context_value();
        let mut exact = rule("allow", 'a');
        exact["scope"][field] = c[field].clone();
        c[field] = Value::Null;
        assert_eq!(evaluate(&[exact], &c).state(), GrantState::None);
        assert_eq!(
            evaluate(&[rule("allow", 'a')], &c).state(),
            GrantState::Explicit
        );
        let parsed = context(&c);
        assert!(match field {
            "principal" => parsed.principal.is_none(),
            "agent" => parsed.agent.is_none(),
            _ => parsed.environment.is_none(),
        });
    }
    let mut c = context_value();
    c["client"] = Value::Null;
    let resolution = evaluate(&[rule("allow", 'a')], &c);
    assert_eq!(resolution.state(), GrantState::None);
    assert_eq!(resolution.reason(), Reason::UnknownClient);
    assert_eq!(
        evaluate(&[rule("deny", 'd')], &c).state(),
        GrantState::Denied
    );
}

#[test]
fn one_allowance_must_cover_whole_action_and_any_denied_class_blocks() {
    let mut c = context_value();
    c["capabilities"] = json!(["read_data", "write_data"]);
    let mut read = rule("allow", 'a');
    read["scope"]["capabilities"] = json!(["read_data"]);
    let mut write = rule("allow", 'b');
    write["scope"]["capabilities"] = json!(["write_data"]);
    assert_eq!(
        evaluate(&[read.clone(), write.clone()], &c).state(),
        GrantState::None
    );
    read["scope"]["capabilities"] = json!(["read_data", "write_data"]);
    assert_eq!(evaluate(&[read.clone()], &c).state(), GrantState::Explicit);
    write["effect"] = json!("deny");
    assert_eq!(
        evaluate(&[read.clone(), write], &c).state(),
        GrantState::Denied
    );
    c["capabilities"] = json!(["unknown"]);
    assert_eq!(evaluate(&[read], &c).state(), GrantState::None);
    // An explicit all-class rule is broad, but is still subject to policy and
    // unknown-tool/approval guards in the enforcing gateway.
    assert_eq!(
        evaluate(&[rule("allow", 'a')], &c).state(),
        GrantState::Explicit
    );
}

#[test]
fn capability_subset_matrix_has_no_union_or_order_bypass() {
    let names = ["read_data", "write_data", "delete_data"];
    for action_mask in 1..8 {
        for grant_mask in 1..8 {
            let classes = |mask| {
                names
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, name)| *name)
                    .collect::<Vec<_>>()
            };
            let mut c = context_value();
            c["capabilities"] = json!(classes(action_mask));
            let mut allowance = rule("allow", 'a');
            allowance["scope"]["capabilities"] = json!(classes(grant_mask));
            let expected = if action_mask & grant_mask == action_mask {
                GrantState::Explicit
            } else {
                GrantState::None
            };
            assert_eq!(evaluate(&[allowance.clone()], &c).state(), expected);
            allowance["effect"] = json!("deny");
            let expected = if action_mask & grant_mask != 0 {
                GrantState::Denied
            } else {
                GrantState::None
            };
            assert_eq!(evaluate(&[allowance], &c).state(), expected);
        }
    }
}

#[test]
fn windows_are_start_inclusive_end_exclusive_for_both_effects() {
    for effect in ["allow", "deny"] {
        let expected = if effect == "allow" {
            GrantState::Explicit
        } else {
            GrantState::Denied
        };
        let mut r = rule(effect, 'a');
        r["scope"]["not_before_ms"] = json!(1000);
        r["scope"]["expires_at_ms"] = json!(2000);
        for (time, state) in [
            (999, GrantState::None),
            (1000, expected),
            (1999, expected),
            (2000, GrantState::None),
        ] {
            let mut c = context_value();
            c["time_ms"] = json!(time);
            assert_eq!(evaluate(&[r.clone()], &c).state(), state);
        }
    }
}

#[test]
fn policy_cannot_override_missing_or_denied_grants() {
    let c = context_value();
    for (rules, allowed) in [
        (vec![], false),
        (vec![rule("deny", 'a')], false),
        (vec![rule("allow", 'a')], true),
    ] {
        let result = evaluate(&rules, &c);
        for policy in [Decision::Deny, Decision::Allow, Decision::RequireApproval] {
            assert_eq!(
                result.constrain(policy),
                if allowed { policy } else { Decision::Deny }
            );
        }
    }
    let empty = parse(&[]).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(
        empty.evaluate(&context(&c)).unwrap().reason(),
        Reason::NoMatchingGrant
    );
}

#[test]
fn missing_or_unknown_fields_never_broaden_rules() {
    for field in [
        "client",
        "principal",
        "agent",
        "server",
        "tool",
        "capabilities",
        "environment",
        "not_before_ms",
        "expires_at_ms",
    ] {
        let mut r = rule("allow", 'a');
        r["scope"].as_object_mut().unwrap().remove(field);
        assert!(
            matches!(parse(&[r]), Err(Error::Rules)),
            "accepted missing {field}"
        );
    }
    for path in [0, 1, 2] {
        let mut doc = json!({"schema_version":1,"grants":[rule("allow", 'a')]});
        match path {
            0 => doc["metadata"] = json!("private-canary"),
            1 => doc["grants"][0]["priority"] = json!(100),
            _ => doc["grants"][0]["scope"]["raw_arguments"] = json!("private-canary"),
        }
        assert!(matches!(
            GrantSet::from_bytes(&serde_json::to_vec(&doc).unwrap()),
            Err(Error::Rules)
        ));
    }
    let r = rule("allow", 'a');
    assert!(parse(&[r.clone(), r]).is_err());
    assert!(GrantSet::from_bytes(br#"{"schema_version":1,"grants":[],"grants":[]}"#).is_err());
    assert!(!Error::Rules.to_string().contains("private-canary"));
}

#[test]
fn malformed_rule_bounds_and_empty_classes_are_rejected() {
    for (field, value) in [
        ("capabilities", json!([])),
        ("capabilities", json!(["read_data", "read_data"])),
        ("capabilities", json!(["invented"])),
        ("client", json!("A".repeat(64))),
        ("environment", json!("")),
        ("environment", json!("x".repeat(65))),
        ("environment", json!("prod\n")),
        ("not_before_ms", json!(-1)),
        ("expires_at_ms", json!(MAX_TIME + 1)),
        ("expires_at_ms", json!(0)),
    ] {
        let mut r = rule("allow", 'a');
        r["scope"][field] = value;
        assert!(parse(&[r]).is_err(), "accepted {field}");
    }
    for end in [1, 1000] {
        let mut r = rule("allow", 'a');
        r["scope"]["not_before_ms"] = json!(1000);
        r["scope"]["expires_at_ms"] = json!(end);
        assert!(parse(&[r]).is_err());
    }
    let mut invalid_effect = rule("allow", 'a');
    invalid_effect["effect"] = json!("require_approval");
    assert!(parse(&[invalid_effect]).is_err());
    assert!(GrantSet::from_bytes(&vec![b' '; MAX_DOCUMENT + 1]).is_err());
    let rules: Vec<_> = (0..=MAX_GRANTS)
        .map(|i| {
            let mut r = rule("allow", 'a');
            r["grant_ref"] = json!(format!("{i:064x}"));
            r
        })
        .collect();
    assert!(parse(&rules).is_err());
    assert_eq!(parse(&rules[..MAX_GRANTS]).unwrap().len(), MAX_GRANTS);
}

#[test]
fn contexts_are_closed_bounded_and_revalidated_at_evaluation() {
    for field in ["client", "principal", "agent", "environment"] {
        let mut c = context_value();
        c.as_object_mut().unwrap().remove(field);
        assert!(GrantContext::from_bytes(&serde_json::to_vec(&c).unwrap()).is_err());
    }
    for (field, value) in [
        ("time_ms", json!(MAX_TIME + 1)),
        ("capabilities", json!([])),
        ("capabilities", json!(["read_data", "read_data"])),
        ("schema_version", json!(2)),
        ("environment", json!("private\ncanary")),
        ("metadata", json!({"secret":"private-canary"})),
    ] {
        let mut c = context_value();
        c[field] = value;
        assert!(GrantContext::from_bytes(&serde_json::to_vec(&c).unwrap()).is_err());
    }
    assert!(GrantContext::from_bytes(&vec![b' '; 4097]).is_err());
    assert!(GrantContext::from_bytes(br#"{"client":null,"client":null}"#).is_err());
    let mut c = context(&context_value());
    let set = parse(&[rule("allow", 'a')]).unwrap();
    c.capabilities.clear();
    assert_eq!(set.evaluate(&c), Err(Error::Context));
    c = context(&context_value());
    c.environment = Some("private-canary\n".into());
    assert_eq!(set.evaluate(&c), Err(Error::Context));
}
