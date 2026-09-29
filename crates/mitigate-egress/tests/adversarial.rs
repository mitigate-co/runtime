//! Fixed and generated hostile inputs exercise the real closed event validator.
use mitigate_egress::{CheckedEvent, MAX_EVENT_BYTES, Rejection};
use serde_json::Value;

const DECISION: &[u8] = include_bytes!("../../../examples/egress/decision.json");
const INVENTORY: &[u8] = include_bytes!("../../../examples/egress/inventory-part.json");
const CANARY: &[u8] = b"synthetic-content-canary";

#[test]
fn saved_hostile_inputs_never_obtain_an_event_or_echo_source_text() {
    for (index, line) in include_str!("hostile-corpus.jsonl").lines().enumerate() {
        let case: Value = serde_json::from_str(line).unwrap();
        let input = match case["kind"].as_str().unwrap() {
            "decision" => DECISION,
            "inventory" => INVENTORY,
            _ => panic!("unsupported corpus kind"),
        };
        // Start each attack from a complete admitted control. Missing required
        // fields must not mask an untested acceptance of the hostile member.
        assert!(CheckedEvent::from_bytes(input).is_ok());
        let mut value: Value = serde_json::from_slice(input).unwrap();
        let object = match case["location"].as_str().unwrap() {
            "envelope" => &mut value,
            "facts" => &mut value["facts"],
            "tool" => &mut value["facts"]["tools"][0],
            _ => panic!("unsupported corpus location"),
        };
        object.as_object_mut().unwrap().insert(
            case["field"].as_str().unwrap().to_owned(),
            case["value"].clone(),
        );
        let candidate = serde_json::to_vec(&value).unwrap();
        let error = CheckedEvent::from_bytes(&candidate)
            .err()
            .expect("hostile corpus admitted");
        assert!(
            !format!("{error:?} {error}").contains("canary"),
            "case {index}"
        );
    }
    // Positive controls catch an implementation that merely rejects everything.
    for input in [DECISION, INVENTORY] {
        assert!(CheckedEvent::from_bytes(input).is_ok());
    }
}

#[test]
fn every_existing_key_rejects_a_duplicate_even_when_unicode_escaped() {
    for input in [DECISION, INVENTORY] {
        let value: Value = serde_json::from_slice(input).unwrap();
        let canonical = value.to_string();
        let mut objects = vec![&value, &value["facts"]];
        if let Some(tools) = value["facts"]["tools"].as_array() {
            objects.extend(tools);
        }
        for object in objects {
            for (key, member) in object.as_object().unwrap() {
                let escaped: String = key.bytes().map(|byte| format!("\\u{byte:04x}")).collect();
                for spelling in [key.to_owned(), escaped] {
                    let original = object.to_string();
                    // Remove only the outer brace: nested objects must stay intact.
                    let duplicate = format!(
                        "{},\"{spelling}\":{member}}}",
                        &original[..original.len() - 1]
                    );
                    let candidate = canonical.replacen(&original, &duplicate, 1);
                    assert!(
                        mitigate_json::parse(candidate.as_bytes()).is_err(),
                        "duplicate {key}"
                    );
                    assert_eq!(
                        CheckedEvent::from_bytes(candidate.as_bytes()).err(),
                        Some(Rejection::Json)
                    );
                }
            }
        }
    }
}

#[test]
fn deterministic_mutations_are_rejected_or_stable_closed_events() {
    let seeds: &[&[u8]] = &[DECISION, INVENTORY, b"{}", b"[]", b"null", b"\xff"];
    let mut random = Generator(0x3d07_88f1);
    let mut admitted = 0;
    let mut rejected = 0;
    for (seed_index, seed) in seeds.iter().enumerate() {
        for case in 0..1024 {
            let mut candidate = seed.to_vec();
            for _ in 0..1 + case % 4 {
                mutate(&mut candidate, &mut random);
            }
            match CheckedEvent::from_bytes(&candidate) {
                Ok(event) => {
                    admitted += 1;
                    assert!(!candidate.windows(CANARY.len()).any(|bytes| bytes == CANARY));
                    assert!(event.as_bytes().len() <= MAX_EVENT_BYTES);
                    assert!(
                        !event
                            .as_bytes()
                            .windows(CANARY.len())
                            .any(|bytes| bytes == CANARY)
                    );
                    let again = CheckedEvent::from_bytes(event.as_bytes()).unwrap();
                    assert!(
                        again.as_bytes() == event.as_bytes(),
                        "unstable seed {seed_index} case {case}"
                    );
                    assert_eq!(again.event_id().as_str(), event.event_id().as_str());
                    assert_eq!(again.runtime_ref().as_str(), event.runtime_ref().as_str());
                }
                Err(error) => {
                    rejected += 1;
                    assert!(!format!("{error:?} {error}").contains("canary"));
                }
            }
        }
    }
    assert!(
        admitted > 0 && rejected > 0,
        "mutation campaign needs both controls"
    );
}

// Fixed xorshift32 is a reproducible mutation selector, never security randomness.
struct Generator(u32);
impl Generator {
    fn index(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0 as usize % bound
    }
}
fn mutate(bytes: &mut Vec<u8>, generator: &mut Generator) {
    let position = generator.index(bytes.len() + 1);
    match generator.index(6) {
        0 if position < bytes.len() => bytes[position] ^= 1 << generator.index(8),
        1 => bytes.insert(position, generator.index(256) as u8),
        2 if position < bytes.len() => {
            bytes.remove(position);
        }
        3 => {
            bytes.truncate(position);
        }
        4 => {
            bytes.splice(position..position, CANARY.iter().copied());
        }
        _ => {
            let tokens: &[&[u8]] = &[b"null", b"{}", b"[]", b"\"", b"\\u0000", b"1e9999", b"\xff"];
            let token = tokens[generator.index(tokens.len())];
            bytes.splice(position..position, token.iter().copied());
        }
    }
}
