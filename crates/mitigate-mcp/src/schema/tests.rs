use super::*;
use serde_json::json;

async fn cases(schema: Value, valid: &[Value], invalid: &[Value]) {
    let compiled = ToolSchema::compile(&schema).await.unwrap();
    for value in valid {
        compiled.validate(value).await.unwrap();
    }
    for value in invalid {
        assert_eq!(compiled.validate(value).await, Err(Error::SchemaMismatch));
    }
}

#[tokio::test]
async fn object_contract_enforces_types_presence_and_closed_fields_without_coercion() {
    cases(json!({"type":"object","properties":{"count":{"type":"integer","minimum":1,"maximum":4},"name":{"type":"string","minLength":2,"maxLength":3},"enabled":{"type":"boolean"}},"required":["count","name"],"additionalProperties":false}),
        &[json!({"count":2,"name":"猫犬"}), json!({"count":4.0,"name":"yes","enabled":false})],
        &[json!({"count":"2","name":"yes"}),json!({"count":2.1,"name":"yes"}),json!({"count":0,"name":"yes"}),json!({"count":5,"name":"yes"}),json!({"count":2}),json!({"count":2,"name":"x"}),json!({"count":2,"name":"long"}),json!({"count":2,"name":"yes","extra":"value-canary"})]).await;
}

#[tokio::test]
async fn applicators_references_dependencies_and_unevaluated_properties_are_enforced() {
    cases(json!({"type":"object","$defs":{"number":{"type":"number","exclusiveMinimum":0,"multipleOf":0.5}},"properties":{"x":{"$ref":"#/$defs/number"},"mode":{"enum":["one","two"]}},"required":["mode"],"dependentRequired":{"x":["mode"]},"if":{"properties":{"mode":{"const":"two"}}},"then":{"required":["x"]},"else":{"not":{"required":["x"]}},"unevaluatedProperties":false}),
        &[json!({"mode":"one"}),json!({"mode":"two","x":1.5})],
        &[json!({"mode":"three"}),json!({"mode":"two"}),json!({"mode":"one","x":1}),json!({"mode":"two","x":0}),json!({"mode":"two","x":1.2}),json!({"mode":"two","x":1,"extra":true})]).await;
    cases(json!({"type":"object","allOf":[{"anyOf":[{"required":["a"]},{"required":["b"]}]}],"oneOf":[{"required":["a"]},{"required":["b"]}],"dependentSchemas":{"a":{"properties":{"a":{"const":1}}}}}),
        &[json!({"a":1}),json!({"b":true})],&[json!({}),json!({"a":2}),json!({"a":1,"b":true})]).await;
}

#[tokio::test]
async fn arrays_contains_patterns_and_property_names_validate_actual_values() {
    cases(json!({"type":"object","properties":{"list":{"type":"array","prefixItems":[{"const":"start"}],"items":{"type":"integer"},"minItems":2,"maxItems":4,"uniqueItems":true,"contains":{"type":"integer","minimum":2},"minContains":1,"maxContains":2}},"required":["list"],"patternProperties":{"^x_":{"type":"string","pattern":"^[a-z]+$"}},"propertyNames":{"pattern":"^[a-z_]+$"},"additionalProperties":false}),
        &[json!({"list":["start",2],"x_name":"abc"})],
        &[json!({"list":["start"]}),json!({"list":["start",1]}),json!({"list":["start",2,2]}),json!({"list":["start",2,3,4]}),json!({"list":["wrong",2]}),json!({"list":["start",2],"x_name":"ABC"}),json!({"list":["start",2],"X":true})]).await;
    cases(json!({"type":"object","properties":{"a":{"type":"array","prefixItems":[true,false],"unevaluatedItems":false}}}),
        &[json!({"a":[1]})],&[json!({"a":[1,2]})]).await;
}

#[tokio::test]
async fn annotations_are_not_constraints_or_defaults_and_data_is_not_a_schema() {
    let original = json!({"value":"not-an-email"});
    let schema = json!({"type":"object","properties":{"value":{"type":"string","format":"email","default":"annotation-canary"}},"examples":[{"$ref":"https://example.invalid/never-fetch"}],"const":{"value":"not-an-email"}});
    let compiled = ToolSchema::compile(&schema).await.unwrap();
    compiled.validate(&original).await.unwrap();
    assert_eq!(original, json!({"value":"not-an-email"}));
    assert_eq!(
        compiled.validate(&json!({})).await,
        Err(Error::SchemaMismatch)
    );
}

#[tokio::test]
async fn unknown_dialects_keywords_external_refs_and_unsupported_regex_fail_closed() {
    for schema in [
        json!({"type":"object","$ref":"https://127.0.0.1:1/credential-canary"}),
        json!({"type":"object","$ref":"file:///credential-canary"}),
        json!({"type":"object","$ref":"relative.json"}),
        json!({"type":"object","$ref":"#/%24defs/a","$defs":{"a":true}}),
        json!({"type":"object","$ref":"#/default","default":false}),
        json!({"type":"object","$schema":"http://json-schema.org/draft-07/schema#"}),
        json!({"type":"object","$id":"https://example.invalid/schema"}),
        json!({"type":"object","$dynamicRef":"#x"}),
        json!({"type":"object","$vocabulary":{"https://example.invalid":true}}),
        json!({"type":"object","require":["typo-canary"]}),
        json!({"type":"object","properties":{"s":{"type":"string","pattern":"(?<=a)b"}}}),
        json!({"type":"object","properties":{"s":{"type":"string","pattern":"(a)\\1"}}}),
        json!({"type":"object","required":1}),
        json!({"type":"object","properties":{"x":{"type":"invalid-type-canary"}}}),
    ] {
        let error = ToolSchema::compile(&schema).await.err().unwrap();
        assert_eq!(error, Error::Schema);
        assert!(!format!("{error:?} {error}").contains("canary"));
    }
}

#[tokio::test]
async fn pointer_escaping_is_exact_and_unused_schema_definitions_are_checked() {
    cases(json!({"type":"object","$defs":{"a/b~c":{"type":"integer"}},"properties":{"v":{"$ref":"#/$defs/a~1b~0c"}}}),
        &[json!({"v":2})],&[json!({"v":"2"})]).await;
    assert_eq!(
        ToolSchema::compile(
            &json!({"type":"object","$defs":{"unused":{"$ref":"https://example.invalid"}}})
        )
        .await
        .err(),
        Some(Error::Schema)
    );
}

#[tokio::test]
async fn cycles_reference_expansion_and_regex_bombs_are_bounded_before_compilation() {
    for schema in [
        json!({"type":"object","$ref":"#"}),
        json!({"type":"object","$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}}}),
        json!({"type":"object","properties":{"x":{"pattern":"a".repeat(257)}}}),
        json!({"type":"object","allOf":vec![json!(true);257]}),
    ] {
        assert_eq!(
            ToolSchema::compile(&schema).await.err(),
            Some(Error::SchemaLimit)
        );
    }
    let mut defs = serde_json::Map::new();
    defs.insert("n0".into(), json!(true));
    for n in 1..12 {
        let reference = format!("#/$defs/n{}", n - 1);
        defs.insert(
            format!("n{n}"),
            json!({"allOf":[{"$ref":reference},{"$ref":reference}]}),
        );
    }
    assert_eq!(
        ToolSchema::compile(&json!({"type":"object","$defs":defs}))
            .await
            .err(),
        Some(Error::SchemaLimit)
    );
    assert_eq!(
        ToolSchema::compile(
            &json!({"type":"object","properties":{"s":{"pattern":"a{999999999}"}}})
        )
        .await
        .err(),
        Some(Error::Schema)
    );
}

#[tokio::test]
async fn large_and_deep_values_are_refused_without_returning_content() {
    let schema = ToolSchema::compile(&json!({"type":"object"}))
        .await
        .unwrap();
    let mut deep = json!(null);
    for _ in 0..34 {
        deep = json!({"x":deep});
    }
    for value in [
        deep,
        json!({"x":vec![0;1025]}),
        json!({"x":"z".repeat(65_537)}),
    ] {
        assert_eq!(schema.validate(&value).await, Err(Error::SchemaLimit));
    }
    let busy = ToolSchema::compile(&json!({"type":"object","allOf":vec![json!(true);128]}))
        .await
        .unwrap();
    let large = json!({"v":vec!["c".repeat(32_768);16]});
    assert_eq!(busy.validate(&large).await, Err(Error::SchemaLimit));
}

#[tokio::test]
async fn waiting_deadline_never_runs_queued_work_and_cancellation_retains_worker_slot() {
    static GATE: Semaphore = Semaphore::const_new(1);
    let permit = GATE.acquire().await.unwrap();
    assert_eq!(
        blocking_with(&GATE, Duration::ZERO, || -> Result<()> {
            panic!("must not run")
        })
        .await,
        Err(Error::SchemaLimit)
    );
    drop(permit);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let mut task = Box::pin(blocking_with(&GATE, Duration::from_secs(5), move || {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        Ok(())
    }));
    tokio::select! {
        result=&mut task=>panic!("worker unexpectedly finished: {result:?}"),
        _=started_rx=>(),
    }
    drop(task);
    assert!(GATE.try_acquire().is_err());
    release_tx.send(()).unwrap();
    let _returned = tokio::time::timeout(Duration::from_secs(5), GATE.acquire())
        .await
        .unwrap()
        .unwrap();
}
