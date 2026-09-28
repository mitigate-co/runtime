//! Fail-closed schema admission before the dependency parser/compiler.
use crate::{Error, Result};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn document(value: &Value, max_bytes: usize) -> Result<usize> {
    fn visit(value: &Value, depth: usize, nodes: &mut usize, text: &mut usize) -> Result<()> {
        *nodes += 1;
        if depth > 32 || *nodes > 32_768 || *text > 1_048_576 {
            return Err(Error::SchemaLimit);
        }
        match value {
            Value::String(s) => {
                if s.len() > 65_536 {
                    return Err(Error::SchemaLimit);
                }
                *text += s.len();
            }
            Value::Array(items) => {
                if items.len() > 1024 {
                    return Err(Error::SchemaLimit);
                }
                for item in items {
                    visit(item, depth + 1, nodes, text)?;
                }
            }
            Value::Object(items) => {
                if items.len() > 1024 {
                    return Err(Error::SchemaLimit);
                }
                for (key, item) in items {
                    if key.len() > 4096 {
                        return Err(Error::SchemaLimit);
                    }
                    *text += key.len();
                    visit(item, depth + 1, nodes, text)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    let (mut nodes, mut text) = (0, 0);
    visit(value, 0, &mut nodes, &mut text)?;
    // Preflight above bounds recursion/allocation even for library-created Value.
    if serde_json::to_vec(value)
        .map_err(|_| Error::SchemaLimit)?
        .len()
        > max_bytes
    {
        return Err(Error::SchemaLimit);
    }
    Ok(nodes + text.div_ceil(16))
}

#[derive(Default)]
struct Node {
    edges: Vec<String>,
    repeats: usize,
}

pub(super) fn check(schema: &Value) -> Result<usize> {
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(Error::Schema);
    }
    let mut graph = BTreeMap::new();
    collect(schema, "#".into(), &mut graph, &mut 0)?;
    fn cost(path: &str, graph: &BTreeMap<String, Node>, chain: &mut Vec<String>) -> Result<usize> {
        if chain.len() >= 32 || chain.iter().any(|p| p == path) {
            return Err(Error::SchemaLimit);
        }
        let node = graph.get(path).ok_or(Error::Schema)?;
        chain.push(path.into());
        let mut total = 1;
        for edge in &node.edges {
            total += cost(edge, graph, chain)?;
            if total > 1024 {
                return Err(Error::SchemaLimit);
            }
        }
        chain.pop();
        total *= node.repeats;
        if total > 1024 {
            return Err(Error::SchemaLimit);
        }
        Ok(total)
    }
    cost("#", &graph, &mut Vec::new())
}

fn child(path: &str, key: &str) -> String {
    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"))
}

fn pattern(value: &str, count: &mut usize) -> Result<()> {
    *count += 1;
    if value.len() > 256 || *count > 32 {
        return Err(Error::SchemaLimit);
    }
    Ok(())
}

fn collect(
    value: &Value,
    path: String,
    graph: &mut BTreeMap<String, Node>,
    patterns: &mut usize,
) -> Result<()> {
    if graph.len() >= 256 {
        return Err(Error::SchemaLimit);
    }
    // Insert before descent so all local JSON pointers resolve to actual schema
    // positions. Objects inside const/default/examples are data, never schemas.
    graph.insert(path.clone(), Node::default());
    let mut node = Node {
        edges: Vec::new(),
        repeats: 1,
    };
    if let Some(map) = value.as_object() {
        for (key, value) in map {
            let location = child(&path, key);
            match key.as_str() {
                "$schema" => {
                    if value.as_str() != Some("https://json-schema.org/draft/2020-12/schema") {
                        return Err(Error::Schema);
                    }
                }
                "$ref" => {
                    let reference = value.as_str().ok_or(Error::Schema)?;
                    if !(reference == "#" || reference.starts_with("#/")) || reference.contains('%')
                    {
                        return Err(Error::Schema);
                    }
                    node.edges.push(reference.into());
                }
                "$defs" | "properties" | "patternProperties" | "dependentSchemas" => {
                    let children = value.as_object().ok_or(Error::Schema)?;
                    for (name, schema) in children {
                        if key == "patternProperties" {
                            pattern(name, patterns)?;
                        }
                        let nested = child(&location, name);
                        collect(schema, nested.clone(), graph, patterns)?;
                        node.edges.push(nested);
                    }
                }
                "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                    for (index, schema) in value.as_array().ok_or(Error::Schema)?.iter().enumerate()
                    {
                        let nested = child(&location, &index.to_string());
                        collect(schema, nested.clone(), graph, patterns)?;
                        node.edges.push(nested);
                    }
                }
                "not"
                | "if"
                | "then"
                | "else"
                | "items"
                | "contains"
                | "additionalProperties"
                | "propertyNames"
                | "unevaluatedProperties"
                | "unevaluatedItems" => {
                    collect(value, location.clone(), graph, patterns)?;
                    node.edges.push(location);
                    // Annotation collection may revisit applicators. Charge
                    // conservatively for each unevaluated-* boundary.
                    if key.starts_with("unevaluated") {
                        node.repeats *= 4;
                    }
                }
                "pattern" => pattern(value.as_str().ok_or(Error::Schema)?, patterns)?,
                // Draft 2020-12 assertions; their types are checked by the
                // offline official meta-schema in the dependency compiler.
                "type" | "enum" | "const" | "multipleOf" | "maximum" | "minimum"
                | "exclusiveMaximum" | "exclusiveMinimum" | "maxLength" | "minLength"
                | "maxItems" | "minItems" | "uniqueItems" | "maxContains" | "minContains"
                | "maxProperties" | "minProperties" | "required" | "dependentRequired" => (),
                // Annotations are not coercion, executable validation or policy.
                "title" | "description" | "$comment" | "default" | "examples" | "deprecated"
                | "readOnly" | "writeOnly" | "format" | "contentEncoding" | "contentMediaType" => {}
                // Reject other dialects, dynamic/remote references, custom
                // vocabularies and unknown keywords instead of ignoring them.
                _ => return Err(Error::Schema),
            }
        }
    } else if !value.is_boolean() {
        return Err(Error::Schema);
    }
    graph.insert(path, node);
    Ok(())
}
