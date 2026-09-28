//! Explicit offline policy tooling. Signing values never enter argv or reports.
use crate::{args::PolicyCommand, output};
use mitigate_policy::{
    Authority, Decision, Error, Policy, PolicyInput, PolicyStore, Receipt, SignedBundle,
    public_key, read_document, write_new,
};
use mitigate_secrets::{NativeStore, Secret, SecretRef, SecretStore};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Serialize)]
#[serde(untagged)]
enum Report {
    Action {
        schema_version: u32,
        action: &'static str,
    },
    Key {
        schema_version: u32,
        action: &'static str,
        secret_ref: String,
        authority: Authority,
    },
    Status(Receipt),
    Decision {
        schema_version: u32,
        decision: Decision,
        policy: Option<Receipt>,
    },
}
fn source(path: &Path) -> Result<String, Error> {
    String::from_utf8(read_document(path, mitigate_policy::MAX_SOURCE)?).map_err(|_| Error::Profile)
}
fn authority(path: &Path) -> Result<Authority, Error> {
    Authority::from_bytes(&read_document(path, 1024)?)
}
fn input(path: &Path) -> Result<PolicyInput, Error> {
    PolicyInput::from_bytes(&read_document(path, 4096)?)
}
fn seed(value: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Key);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    for (i, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let n = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes[i] = n(chunk[0]) * 16 + n(chunk[1]);
    }
    Ok(bytes)
}
fn hex(bytes: &[u8]) -> Zeroizing<String> {
    use std::fmt::Write;
    let mut value = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        write!(&mut *value, "{byte:02x}").expect("string writes cannot fail");
    }
    value
}
async fn generate(trust_out: &Path) -> Result<Report, Error> {
    // Refuse obvious collisions before generating/store operations. Exclusive
    // creation below still handles races and rolls back this exact owned key.
    if trust_out.exists() {
        return Err(Error::Path);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| Error::Key)?;
    let mut identifier = [0u8; 32];
    getrandom::fill(&mut identifier).map_err(|_| Error::Key)?;
    let policy_ref =
        serde_json::from_value(serde_json::Value::String(hex(&identifier).to_string()))
            .map_err(|_| Error::Key)?;
    let authority = Authority {
        schema_version: 1,
        policy_ref,
        public_key: public_key(&bytes),
    };
    let reference = SecretRef::generate().map_err(|_| Error::Key)?;
    match NativeStore.read(&reference).await {
        Err(mitigate_secrets::Error::Missing) => (),
        _ => return Err(Error::Key),
    }
    let mut encoded = hex(&*bytes);
    let secret =
        Secret::from_bytes(std::mem::take(&mut *encoded).into_bytes()).map_err(|_| Error::Key)?;
    NativeStore
        .put(&reference, secret)
        .await
        .map_err(|_| Error::Key)?;
    let document = serde_json::to_vec_pretty(&authority).map_err(|_| Error::Signature)?;
    if let Err(error) = write_new(trust_out, &document) {
        // Never enumerate or delete another credential. A failed native cleanup
        // remains a safe orphan; no seed or reference is guessed or retried.
        let _ = NativeStore.delete(&reference).await;
        return Err(error);
    }
    Ok(Report::Key {
        schema_version: 1,
        action: "key_created",
        secret_ref: reference.as_str().into(),
        authority,
    })
}
async fn execute(command: PolicyCommand) -> Result<Report, Error> {
    match command {
        PolicyCommand::Check { source: path } => {
            Policy::compile(&source(&path)?)?;
            Ok(Report::Action {
                schema_version: 1,
                action: "profile_valid",
            })
        }
        PolicyCommand::Test {
            source: path,
            input: data,
        } => {
            let decision = Policy::compile(&source(&path)?)?.evaluate(&input(&data)?)?;
            Ok(Report::Decision {
                schema_version: 1,
                decision,
                policy: None,
            })
        }
        PolicyCommand::Keygen { trust_out } => generate(&trust_out).await,
        PolicyCommand::Sign {
            source: path,
            trust,
            key_ref,
            version,
            out,
        } => {
            let authority = authority(&trust)?;
            let source = source(&path)?;
            Policy::compile(&source)?;
            if !(1..=9_007_199_254_740_991).contains(&version) || out.exists() {
                return Err(Error::Input);
            }
            let reference = SecretRef::parse(&key_ref).map_err(|_| Error::Key)?;
            let secret = NativeStore.read(&reference).await.map_err(|_| Error::Key)?;
            let bytes = secret.expose(seed)?;
            drop(secret);
            if public_key(&bytes) != authority.public_key {
                return Err(Error::Signature);
            }
            let bundle = SignedBundle::sign(authority.policy_ref.clone(), version, source, &bytes)?;
            drop(bytes);
            let verified = bundle.verify(&authority)?;
            write_new(&out, &bundle.to_bytes()?)?;
            Ok(Report::Status(verified.receipt().clone()))
        }
        PolicyCommand::Init { db, trust } => {
            PolicyStore::create(&db, authority(&trust)?)?;
            Ok(Report::Action {
                schema_version: 1,
                action: "store_created",
            })
        }
        PolicyCommand::Activate { db, trust, bundle } => {
            let bundle = SignedBundle::from_bytes(&read_document(&bundle, 32_768)?)?;
            let policy = PolicyStore::open(&db, authority(&trust)?)?.activate(&bundle)?;
            Ok(Report::Status(policy.receipt().clone()))
        }
        PolicyCommand::Status { db, trust } => {
            let policy = PolicyStore::open(&db, authority(&trust)?)?.load()?;
            Ok(Report::Status(policy.receipt().clone()))
        }
        PolicyCommand::Evaluate {
            db,
            trust,
            input: data,
        } => {
            let mut policy = PolicyStore::open(&db, authority(&trust)?)?.load()?;
            let decision = policy.evaluate(&input(&data)?)?;
            Ok(Report::Decision {
                schema_version: 1,
                decision,
                policy: Some(policy.receipt().clone()),
            })
        }
    }
}
pub(crate) fn run(command: PolicyCommand, machine: bool) -> io::Result<ExitCode> {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
        .map_err(|_| Error::Key)
        .and_then(|runtime| {
            let result = runtime.block_on(execute(command));
            runtime.shutdown_timeout(Duration::from_millis(50));
            result
        });
    match result {
        Ok(report) => {
            if machine {
                output::json(&report, io::stdout().lock())?;
            } else {
                let mut out = io::stdout().lock();
                match report {
                    Report::Action { action, .. } => {
                        writeln!(out, "Policy: {}.", action.replace('_', " "))?
                    }
                    Report::Key { secret_ref, .. } => writeln!(
                        out,
                        "Signing key stored locally. Reference: {secret_ref}\nPublic trust document created."
                    )?,
                    Report::Status(receipt) => writeln!(
                        out,
                        "Verified policy version {}. Bundle: {}",
                        receipt.version, receipt.bundle_hash
                    )?,
                    Report::Decision { decision, .. } => writeln!(
                        out,
                        "Decision: {}. No tool invoked.",
                        match decision {
                            Decision::Allow => "allow",
                            Decision::Deny => "deny",
                            Decision::RequireApproval => "require approval",
                        }
                    )?,
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            output::error(error.code(), &error.to_string(), machine)?;
            Ok(ExitCode::from(2))
        }
    }
}
