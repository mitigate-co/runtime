//! Standalone offline demonstration, using only the checked-in synthetic catalog.
use mitigate_registry::Catalog;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::from_bytes(include_bytes!("../../../examples/registry/catalog.json"))?;
    let report = catalog.lookup("io.example/synthetic-server", 1_790_553_600_000)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
