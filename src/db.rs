use lightning_invoice::Bolt11Invoice;
use nostr::Event;
use serde::{Deserialize, Serialize};
use sled::Db;

/// Data structure for storing information about a lightning invoice and its associated Nostr zap request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zap {
    pub invoice: Bolt11Invoice,
    pub request: Event,
    pub note_id: Option<String>,
}

/// Stores or updates a Zap record in the database.
///
/// # Parameters
/// * `db` - The database instance
/// * `payment_hash` - The payment hash used as the key for storage
/// * `zap` - The Zap record to be stored
///
/// # Returns
/// `Ok(())` if the operation is successful, or an error if it fails
pub fn upsert_zap(db: &Db, payment_hash: String, zap: Zap) -> anyhow::Result<()> {
    let value = serde_json::to_vec(&zap)?;
    db.insert(payment_hash.as_bytes(), value)?;

    Ok(())
}

/// Retrieves a Zap record from the database using the payment hash as the key.
///
/// # Parameters
/// * `db` - The database instance
/// * `payment_hash` - The payment hash key to look up
///
/// # Returns
/// `Ok(Some(Zap))` if the record is found, `Ok(None)` if not found, 
/// or an error if the retrieval or deserialization fails
pub fn get_zap(db: &Db, payment_hash: String) -> anyhow::Result<Option<Zap>> {
    let value = db.get(payment_hash.as_bytes())?;

    match value {
        Some(value) => {
            let zap = serde_json::from_slice(&value)?;
            Ok(Some(zap))
        }
        None => Ok(None),
    }
}
