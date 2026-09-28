use crate::{Error, SERVICE, Secret, SecretRef};
use secret_service::{EncryptionType, Item, SecretService};
use std::collections::HashMap;

async fn connect() -> Result<SecretService<'static>, Error> {
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|_| Error::Unavailable)
}
fn attributes(reference: &SecretRef) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE), ("username", reference.as_str())])
}
async fn find<'a>(
    service: &'a SecretService<'a>,
    reference: &SecretRef,
) -> Result<Item<'a>, Error> {
    let found = service
        .search_items(attributes(reference))
        .await
        .map_err(|_| Error::Unavailable)?;
    if !found.locked.is_empty() || found.unlocked.len() > 1 {
        return Err(Error::Unavailable);
    }
    found.unlocked.into_iter().next().ok_or(Error::Missing)
}
pub async fn read(reference: &SecretRef) -> Result<Secret, Error> {
    let service = connect().await?;
    let item = find(&service, reference).await?;
    Secret::from_bytes(item.get_secret().await.map_err(|_| Error::Unavailable)?)
}
pub async fn put(reference: &SecretRef, secret: Secret) -> Result<(), Error> {
    let service = connect().await?;
    match find(&service, reference).await {
        Ok(item) => item
            .set_secret(&secret.0, "text/plain")
            .await
            .map_err(|_| Error::Unavailable),
        Err(Error::Missing) => {
            let collection = service
                .get_default_collection()
                .await
                .map_err(|_| Error::Unavailable)?;
            if collection
                .is_locked()
                .await
                .map_err(|_| Error::Unavailable)?
            {
                return Err(Error::Unavailable);
            }
            collection
                .create_item(
                    "Mitigate credential",
                    attributes(reference),
                    &secret.0,
                    false,
                    "text/plain",
                )
                .await
                .map_err(|_| Error::Unavailable)?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}
pub async fn delete(reference: &SecretRef) -> Result<(), Error> {
    let service = connect().await?;
    find(&service, reference)
        .await?
        .delete()
        .await
        .map_err(|_| Error::Unavailable)
}
