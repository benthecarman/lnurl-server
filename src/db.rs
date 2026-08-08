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
pub fn get_zap(db: &Db, payment_hash: &str) -> anyhow::Result<Option<Zap>> {
    let value = db.get(payment_hash.as_bytes())?;

    match value {
        Some(value) => {
            let zap = serde_json::from_slice(&value)?;
            Ok(Some(zap))
        }
        None => Ok(None),
    }
}

/// Atomically marks a Zap record as being processed.
///
/// Uses a compare-and-swap so that only one concurrent settlement handler can
/// claim the zap; losers of the race get `Ok(false)`. A record that is claimed
/// but never finished (e.g. the process crashed mid-broadcast) keeps the marker
/// and is skipped on replay, favoring a lost receipt over a duplicate one.
///
/// # Parameters
/// * `db` - The database instance
/// * `payment_hash` - The payment hash key of the record to claim
/// * `zap` - The Zap record as currently stored (with `note_id` unset)
///
/// # Returns
/// `Ok(true)` if the record was claimed, `Ok(false)` if it was already
/// claimed or processed, or an error if the operation fails
pub fn claim_zap(db: &Db, payment_hash: &str, zap: &Zap) -> anyhow::Result<bool> {
    let old = serde_json::to_vec(zap)?;

    let mut claimed = zap.clone();
    claimed.note_id = Some(String::from("processing"));
    let new = serde_json::to_vec(&claimed)?;

    let result = db.compare_and_swap(payment_hash.as_bytes(), Some(old), Some(new))?;

    Ok(result.is_ok())
}

/// Removes a Zap record from the database.
///
/// Called once the zap receipt has been broadcast, so that zap data is not
/// retained indefinitely and replayed settlements find nothing to redo.
///
/// # Parameters
/// * `db` - The database instance
/// * `payment_hash` - The payment hash key of the record to remove
///
/// # Returns
/// `Ok(())` if the operation is successful, or an error if it fails
pub fn remove_zap(db: &Db, payment_hash: &str) -> anyhow::Result<()> {
    db.remove(payment_hash.as_bytes())?;

    Ok(())
}
