//! App registration (CP3): trusted publishers + registered apps.
//!
//! An app registers by submitting a declaration (identifier, display name,
//! publisher, its own Ed25519 key, schema version, resource types) **signed by
//! a trusted publisher's key**. Hearth verifies the signature against the named
//! trusted publisher's verifying key — so only apps a publisher the Owner
//! trusts can register. See `design/platform.md` §App Registration.
//!
//! Storage fns are executor-generic so a caller can run an upsert + its audit
//! event in one transaction.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// The signed-over fields of an app registration (everything except the
/// signature itself). Both the publisher (when signing) and Hearth (when
/// verifying) canonicalize *these* bytes — see [`canonical_declaration_bytes`].
pub struct AppDeclaration {
    pub app_identifier: String,
    pub display_name: String,
    pub publisher: String,
    pub app_public_key: Vec<u8>,
    pub schema_version: i32,
    pub resource_types: Vec<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RegisteredAppRow {
    pub id: Uuid,
    pub app_identifier: String,
    pub display_name: String,
    pub publisher: String,
    pub app_public_key: Vec<u8>,
    pub schema_version: i32,
    pub resource_types: Vec<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TrustedPublisherRow {
    pub publisher: String,
    pub public_key: Vec<u8>,
}

const APP_COLS: &str = "id, app_identifier, display_name, publisher, app_public_key, \
     schema_version, resource_types, status, created_at, updated_at";

/// Lowercase hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Deterministic byte encoding of a declaration for signing/verification.
/// Domain-separated + fixed field order; `resource_types` sorted so ordering
/// can't change the signed bytes. The publisher signs exactly these bytes.
pub fn canonical_declaration_bytes(decl: &AppDeclaration) -> Vec<u8> {
    let mut types = decl.resource_types.clone();
    types.sort();
    format!(
        "sylva-app-registration:v1\n\
         app_identifier={}\n\
         display_name={}\n\
         publisher={}\n\
         schema_version={}\n\
         app_public_key={}\n\
         resource_types={}",
        decl.app_identifier,
        decl.display_name,
        decl.publisher,
        decl.schema_version,
        hex(&decl.app_public_key),
        types.join(","),
    )
    .into_bytes()
}

/// Verify a publisher's Ed25519 signature over a declaration. Returns false on
/// any malformed key/signature or a mismatch — never panics.
pub fn verify_declaration_signature(
    publisher_public_key: &[u8],
    decl: &AppDeclaration,
    signature: &[u8],
) -> bool {
    let Ok(vk_bytes): Result<[u8; 32], _> = publisher_public_key.try_into() else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(&canonical_declaration_bytes(decl), &signature)
        .is_ok()
}

/// Look up a trusted publisher's verifying key.
pub async fn get_trusted_publisher<'e, E>(
    db: E,
    publisher: &str,
) -> Result<Option<TrustedPublisherRow>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, TrustedPublisherRow>(
        "SELECT publisher, public_key FROM platform.trusted_publishers WHERE publisher = $1",
    )
    .bind(publisher)
    .fetch_optional(db)
    .await
}

/// Add (or replace) a trusted publisher's key.
pub async fn add_trusted_publisher<'e, E>(
    db: E,
    publisher: &str,
    public_key: &[u8],
    added_by: Option<Uuid>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO platform.trusted_publishers (publisher, public_key, added_by)
         VALUES ($1, $2, $3)
         ON CONFLICT (publisher) DO UPDATE
             SET public_key = $2, added_by = $3, added_at = now()",
    )
    .bind(publisher)
    .bind(public_key)
    .bind(added_by)
    .execute(db)
    .await?;
    Ok(())
}

/// Fetch a registered app by its server id.
pub async fn get_app<'e, E>(db: E, id: Uuid) -> Result<Option<RegisteredAppRow>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let sql = format!("SELECT {APP_COLS} FROM platform.registered_apps WHERE id = $1");
    sqlx::query_as::<_, RegisteredAppRow>(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
}

/// Fetch a registered app by its app identifier.
pub async fn get_app_by_identifier<'e, E>(
    db: E,
    app_identifier: &str,
) -> Result<Option<RegisteredAppRow>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let sql = format!("SELECT {APP_COLS} FROM platform.registered_apps WHERE app_identifier = $1");
    sqlx::query_as::<_, RegisteredAppRow>(&sql)
        .bind(app_identifier)
        .fetch_optional(db)
        .await
}

/// Insert or update an app registration (keyed on `app_identifier`). A
/// re-registration updates the mutable fields; ownership (`registered_by`) and
/// `status` are preserved. Caller verifies the publisher signature first.
pub async fn upsert_app<'e, E>(
    db: E,
    decl: &AppDeclaration,
    registered_by: Option<Uuid>,
) -> Result<RegisteredAppRow, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let sql = format!(
        "INSERT INTO platform.registered_apps
             (app_identifier, display_name, publisher, app_public_key,
              schema_version, resource_types, registered_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (app_identifier) DO UPDATE
             SET display_name = $2, publisher = $3, app_public_key = $4,
                 schema_version = $5, resource_types = $6, updated_at = now()
         RETURNING {APP_COLS}"
    );
    sqlx::query_as::<_, RegisteredAppRow>(&sql)
        .bind(&decl.app_identifier)
        .bind(&decl.display_name)
        .bind(&decl.publisher)
        .bind(&decl.app_public_key)
        .bind(decl.schema_version)
        .bind(&decl.resource_types)
        .bind(registered_by)
        .fetch_one(db)
        .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample() -> AppDeclaration {
        AppDeclaration {
            app_identifier: "garden.ubivera.tasks".to_string(),
            display_name: "Tasks".to_string(),
            publisher: "Ubivera, LLC".to_string(),
            app_public_key: vec![7u8; 32],
            schema_version: 1,
            resource_types: vec!["task".to_string(), "project".to_string()],
        }
    }

    #[test]
    fn canonical_bytes_are_order_independent_for_resource_types() {
        let mut a = sample();
        let mut b = sample();
        a.resource_types = vec!["task".into(), "project".into()];
        b.resource_types = vec!["project".into(), "task".into()];
        assert_eq!(canonical_declaration_bytes(&a), canonical_declaration_bytes(&b));
    }

    #[test]
    fn verify_accepts_a_valid_signature_and_rejects_tampering() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let vk = signing.verifying_key();
        let decl = sample();
        let sig = signing.sign(&canonical_declaration_bytes(&decl));

        assert!(verify_declaration_signature(vk.as_bytes(), &decl, &sig.to_bytes()));

        // Tampered declaration → invalid.
        let mut tampered = sample();
        tampered.display_name = "Evil".to_string();
        assert!(!verify_declaration_signature(vk.as_bytes(), &tampered, &sig.to_bytes()));

        // Wrong key → invalid.
        let other = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        assert!(!verify_declaration_signature(other.as_bytes(), &decl, &sig.to_bytes()));

        // Malformed inputs → false, not panic.
        assert!(!verify_declaration_signature(&[0u8; 5], &decl, &sig.to_bytes()));
        assert!(!verify_declaration_signature(vk.as_bytes(), &decl, &[0u8; 3]));
    }
}
