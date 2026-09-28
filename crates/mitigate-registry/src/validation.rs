use crate::{Assertion, Ecosystem, Error};
use url::{Host, Url};

pub(crate) const MAX_TIME: u64 = 253_402_300_799_999;

pub(crate) fn slug(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text.as_bytes()[0].is_ascii_alphanumeric()
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !text.contains("..")
}
pub(crate) fn subject(text: &str) -> bool {
    if text.len() > 192 {
        return false;
    }
    let Some((namespace, name)) = text.split_once('/') else {
        return false;
    };
    namespace.split('.').count() >= 2
        && namespace.split('.').all(|part| {
            slug(part, 63) && !part.contains('_') && !part.starts_with('-') && !part.ends_with('-')
        })
        && slug(name, 64)
}
pub(crate) fn public_url(text: &str) -> bool {
    if text.len() > 2048 || !text.is_ascii() || text.bytes().any(|b| b.is_ascii_control()) {
        return false;
    }
    let Ok(url) = Url::parse(text) else {
        return false;
    };
    let Some(Host::Domain(host)) = url.host() else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.port().is_none()
        && url.as_str() == text
        && host.contains('.')
        && !host.ends_with('.')
        && !["localhost", "local", "internal", "home", "lan"]
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}
fn version(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.as_bytes()[0].is_ascii_alphanumeric()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        && !text.contains("..")
}
fn package(ecosystem: Ecosystem, name: &str) -> bool {
    match ecosystem {
        Ecosystem::Npm => {
            if let Some(scoped) = name.strip_prefix('@') {
                scoped
                    .split_once('/')
                    .is_some_and(|(scope, name)| slug(scope, 64) && slug(name, 128))
            } else {
                slug(name, 128)
            }
        }
        Ecosystem::Pypi => {
            slug(name, 128)
                && !name.contains(['.', '_'])
                && !name.ends_with('-')
                && !name.contains("--")
        }
        Ecosystem::CratesIo => slug(name, 64) && !name.contains('.'),
    }
}
fn advisory(id: &str) -> bool {
    if let Some(value) = id.strip_prefix("CVE-") {
        return value.split_once('-').is_some_and(|(year, number)| {
            year.len() == 4
                && year.bytes().all(|b| b.is_ascii_digit())
                && (4..=10).contains(&number.len())
                && number.bytes().all(|b| b.is_ascii_digit())
        });
    }
    if let Some(value) = id.strip_prefix("GHSA-") {
        let groups: Vec<_> = value.split('-').collect();
        return groups.len() == 3
            && groups
                .iter()
                .all(|g| g.len() == 4 && g.bytes().all(|b| b"23456789cfghjmpqrvwx".contains(&b)));
    }
    false
}
pub(crate) fn assertion(value: &Assertion, observed: u64) -> Result<(), Error> {
    let valid = match value {
        Assertion::Repository { url } => public_url(url),
        Assertion::Package {
            ecosystem,
            name,
            version: release,
        } => package(*ecosystem, name) && version(release),
        Assertion::Transport { .. } | Assertion::Capability { .. } => true,
        Assertion::Release {
            version: release,
            published_at_ms,
        } => version(release) && *published_at_ms <= observed,
        Assertion::Advisory { advisory_id, url } => advisory(advisory_id) && public_url(url),
    };
    if valid { Ok(()) } else { Err(Error::Content) }
}
