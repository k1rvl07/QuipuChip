//! PMX1 export/import, ported from the `exportHandler` / `importHandler` of the
//! removed C++ reference.
//!
//! Unlike the on-flash container (PMV1, binary), PMX1 is **JSON**:
//!
//! ```json
//! {"ok":true,"format":"PMX1","version":1,"count":N,"entries":[ ... ]}
//! ```
//!
//! Each entry carries all seven string fields, plaintext password and TOTP
//! secret included (the session is the only guard). The record `id` is **not**
//! exported: it is reassigned by [`crate::vault::Vault::add`] on import, so a
//! restore into a different vault never reuses another device's ids.
//!
//! The C++ handler streams the document (a full vault does not fit the 8 KiB
//! request/response cap), so this module exposes the pieces separately:
//! [`export_head`], [`encode_entry`], [`export_tail`]. [`export_document`]
//! assembles them for host tests and small exports.
//!
//! Import is batched: `POST /api/import` carries at most
//! [`crate::config::IMPORT_BATCH_ENTRIES`] (4) entries per request. The whole
//! batch is validated before anything is added, so a malformed entry rejects the
//! batch atomically.

use alloc::{format, string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{EXPORT_MAGIC, EXPORT_VERSION, IMPORT_BATCH_ENTRIES};
use crate::entry::{Entry, FIELD_KEYS, Field};
use crate::totp;

/// `format` field of an export/import document (`config::kExportMagic`).
pub const FORMAT: &str = "PMX1";
const _: () = assert!(FORMAT.len() == EXPORT_MAGIC.len());
const _: () = {
    let f = FORMAT.as_bytes();
    let mut i = 0;
    while i < f.len() {
        assert!(f[i] == EXPORT_MAGIC[i]);
        i += 1;
    }
};

/// One entry as it appears on the wire. Field order is the serialization order
/// serde emits and matches the C++ insertion order exactly. `totpDigits` and
/// `totpPeriod` default when absent, so documents written before they existed
/// still import.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pmx1Entry {
    /// Entry title.
    pub title: String,
    /// Login/username.
    pub login: String,
    /// Password or secret.
    pub password: String,
    /// URL.
    pub url: String,
    /// Free-form note.
    pub note: String,
    /// Space-separated tags.
    pub tags: String,
    /// TOTP secret (base32).
    pub totp: String,
    /// TOTP digit count (decimal ASCII; empty = default).
    #[serde(default, rename = "totpDigits")]
    pub totp_digits: String,
    /// TOTP period in seconds (decimal ASCII; empty = default).
    #[serde(default, rename = "totpPeriod")]
    pub totp_period: String,
}

impl Pmx1Entry {
    /// Reads a vault record into an export entry. Stored strings are UTF-8 by
    /// construction; undecodable bytes (flash corruption) are replaced rather
    /// than dropped.
    #[must_use]
    pub fn from_entry(e: &Entry) -> Self {
        let s = |f: Field| String::from_utf8_lossy(e.get(f)).into_owned();
        Self {
            title: s(Field::Title),
            login: s(Field::Login),
            password: s(Field::Password),
            url: s(Field::Url),
            note: s(Field::Note),
            tags: s(Field::Tags),
            totp: s(Field::Totp),
            totp_digits: s(Field::TotpDigits),
            totp_period: s(Field::TotpPeriod),
        }
    }

    /// Builds a vault record with `id = 0` (assigned on `add`). Values are
    /// truncated to the field capacity by [`Entry::set`]; callers that need to
    /// reject oversize values must check first (the import path does, via
    /// [`parse_import`]).
    #[must_use]
    pub fn into_entry(&self) -> Entry {
        let mut e = Entry::new();
        e.set(Field::Title, self.title.as_bytes());
        e.set(Field::Login, self.login.as_bytes());
        e.set(Field::Password, self.password.as_bytes());
        e.set(Field::Url, self.url.as_bytes());
        e.set(Field::Note, self.note.as_bytes());
        e.set(Field::Tags, self.tags.as_bytes());
        e.set(Field::Totp, self.totp.as_bytes());
        e.set(Field::TotpDigits, self.totp_digits.as_bytes());
        e.set(Field::TotpPeriod, self.totp_period.as_bytes());
        e
    }
}

/// Opening bytes of a streamed export up to and including `"entries":[`.
#[must_use]
pub fn export_head(count: usize) -> String {
    format!(
        "{{\"ok\":true,\"format\":\"{FORMAT}\",\"version\":{EXPORT_VERSION},\"count\":{count},\"entries\":["
    )
}

/// Closing bytes of a streamed export.
pub const EXPORT_TAIL: &str = "]}";

/// Serializes one record. Never fails for values produced by [`Pmx1Entry`].
#[must_use]
#[allow(clippy::expect_used, reason = "Pmx1Entry is all strings, cannot fail")]
pub fn encode_entry(e: &Entry) -> String {
    serde_json::to_string(&Pmx1Entry::from_entry(e)).expect("PMX1 entry serializes")
}

/// Whole export document, for tests and limited exports.
#[must_use]
pub fn export_document(entries: &[Entry]) -> String {
    let mut out = export_head(entries.len());
    for (i, e) in entries.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        out.push_str(&encode_entry(e));
    }
    out.push_str(EXPORT_TAIL);
    out
}

/// Reasons an import document is refused. `code` mirrors the `error` string the
/// C++ handler returns, so the HTTP layer stays byte-compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// The `format` field is missing.
    FormatRequired,
    /// The `version` field is not supported.
    VersionUnsupported,
    /// The `entries` array is missing.
    EntriesRequired,
    /// The document contained no importable entries.
    NothingToImport,
    /// The batch exceeds the per-request entry limit.
    BatchTooLarge,
    /// An entry was not a JSON object.
    EntryNotAnObject,
    /// A field was too long or not a string.
    FieldTooLongOrNotString,
    /// A `totp` value was not a valid base32 secret.
    TotpSecretInvalid,
    /// A `totpDigits`/`totpPeriod` value was not a valid number or out of range.
    TotpParamsInvalid,
}

impl ImportError {
    /// Wire code the HTTP layer returns for this refusal.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            ImportError::FormatRequired => "format_required",
            ImportError::VersionUnsupported => "version_unsupported",
            ImportError::EntriesRequired => "entries_required",
            ImportError::NothingToImport => "nothing_to_import",
            ImportError::BatchTooLarge => "batch_too_large",
            ImportError::EntryNotAnObject => "entry_not_an_object",
            ImportError::FieldTooLongOrNotString => "field_too_long_or_not_a_string",
            ImportError::TotpSecretInvalid => "totp_secret_invalid",
            ImportError::TotpParamsInvalid => "totp_params_invalid",
        }
    }
}

impl core::fmt::Display for ImportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl core::error::Error for ImportError {}

/// Parses and fully validates one import batch. On success the returned records
/// are ready for `Vault::add` (ids are zero). Any error rejects the batch before
/// a single record is written.
pub fn parse_import(value: &Value) -> Result<Vec<Entry>, ImportError> {
    if value.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(ImportError::FormatRequired);
    }
    if value.get("version").and_then(Value::as_u64) != Some(u64::from(EXPORT_VERSION)) {
        return Err(ImportError::VersionUnsupported);
    }
    let entries = value
        .get("entries")
        .and_then(Value::as_array)
        .ok_or(ImportError::EntriesRequired)?;
    if entries.is_empty() {
        return Err(ImportError::NothingToImport);
    }
    if entries.len() > IMPORT_BATCH_ENTRIES {
        return Err(ImportError::BatchTooLarge);
    }

    let mut out = Vec::with_capacity(entries.len());
    for raw in entries {
        let obj = raw.as_object().ok_or(ImportError::EntryNotAnObject)?;
        let mut e = Entry::new();
        for (key, field) in FIELD_KEYS {
            // Absent and `null` both mean "empty" (C++ `fillField` semantics).
            match obj.get(*key) {
                None | Some(Value::Null) => {}
                Some(Value::String(s)) => {
                    if s.len() >= e.raw(*field).len() {
                        return Err(ImportError::FieldTooLongOrNotString);
                    }
                    e.set(*field, s.as_bytes());
                }
                Some(_) => return Err(ImportError::FieldTooLongOrNotString),
            }
        }
        if !e.get(Field::Totp).is_empty() {
            core::str::from_utf8(e.get(Field::Totp))
                .ok()
                .filter(|s| totp::is_valid_secret(s))
                .ok_or(ImportError::TotpSecretInvalid)?;
        }
        if totp::resolve_digits(e.get(Field::TotpDigits)).is_none() {
            return Err(ImportError::TotpParamsInvalid);
        }
        if totp::resolve_period(e.get(Field::TotpPeriod)).is_none() {
            return Err(ImportError::TotpParamsInvalid);
        }
        out.push(e);
    }
    Ok(out)
}

/// Parses an import batch from raw request bytes. Malformed JSON is the caller's
/// concern (`malformed_json` is checked before this), so parse failures here map
/// to `format_required` like any other non-object document.
pub fn parse_import_bytes(body: &[u8]) -> Result<Vec<Entry>, ImportError> {
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => parse_import(&v),
        Err(_) => Err(ImportError::FormatRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{ENTRY_NOTE, ENTRY_TITLE};

    fn sample() -> Entry {
        let mut e = Entry::new();
        e.id = 42;
        e.set(Field::Title, b"Mail");
        e.set(Field::Login, b"user@example.com");
        e.set(Field::Password, b"hunter2");
        e.set(Field::Url, b"https://mail.example.com");
        e.set(Field::Note, b"primary");
        e.set(Field::Tags, b"work");
        e.set(Field::Totp, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        e.set(Field::TotpDigits, b"8");
        e.set(Field::TotpPeriod, b"60");
        e
    }

    #[test]
    fn entry_json_field_order_and_no_id() {
        let json = encode_entry(&sample());
        let want = "{\"title\":\"Mail\",\"login\":\"user@example.com\",\
\"password\":\"hunter2\",\"url\":\"https://mail.example.com\",\"note\":\"primary\",\
\"tags\":\"work\",\"totp\":\"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\",\
\"totpDigits\":\"8\",\"totpPeriod\":\"60\"}";
        assert_eq!(json, want);
        assert!(!json.contains("\"id\""));
    }

    #[test]
    fn document_roundtrip_via_import() {
        let entries = vec![sample(), sample()];
        let doc = export_document(&entries);
        assert!(doc.starts_with(
            "{\"ok\":true,\"format\":\"PMX1\",\"version\":1,\"count\":2,\"entries\":["
        ));
        assert!(doc.ends_with("]}"));
        let value: Value = serde_json::from_str(&doc).unwrap();
        let back = parse_import(&value).unwrap();
        assert_eq!(back.len(), 2);
        // ids are not exported; imported records carry id 0.
        assert_eq!(back[0].id, 0);
        assert_eq!(back[0].get_str(Field::Title).unwrap(), "Mail");
        assert_eq!(
            back[0].get_str(Field::Totp).unwrap(),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(back[0].get_str(Field::TotpDigits).unwrap(), "8");
        assert_eq!(back[0].get_str(Field::TotpPeriod).unwrap(), "60");
    }

    #[test]
    fn import_old_document_without_totp_params() {
        // A document from before totpDigits/totpPeriod existed.
        let doc: Value = serde_json::json!({
            "format": "PMX1",
            "version": 1,
            "entries": [{"title": "T", "totp": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}],
        });
        let back = parse_import(&doc).unwrap();
        assert!(back[0].get(Field::TotpDigits).is_empty());
        assert!(back[0].get(Field::TotpPeriod).is_empty());
    }

    #[test]
    fn import_rejects_bad_totp_params() {
        for bad in [
            serde_json::json!({"title":"T","totpDigits":"9"}),
            serde_json::json!({"title":"T","totpPeriod":"5"}),
            serde_json::json!({"title":"T","totpPeriod":"abc"}),
        ] {
            let doc = serde_json::json!({
                "format": "PMX1",
                "version": 1,
                "entries": [bad],
            });
            assert_eq!(
                parse_import(&doc).unwrap_err(),
                ImportError::TotpParamsInvalid
            );
        }
    }

    #[test]
    fn import_absent_and_null_fields_are_empty() {
        let doc: Value = serde_json::json!({
            "format": "PMX1",
            "version": 1,
            "entries": [{"title": "T", "note": null}],
        });
        let back = parse_import(&doc).unwrap();
        assert_eq!(back[0].get_str(Field::Title).unwrap(), "T");
        assert!(back[0].get(Field::Login).is_empty());
        assert!(back[0].get(Field::Note).is_empty());
    }

    #[test]
    fn import_rejects_each_contract_error() {
        let cases = [
            (
                serde_json::json!({"version":1,"entries":[{}]}),
                ImportError::FormatRequired,
            ),
            (
                serde_json::json!({"format":"PMX1","entries":[{}]}),
                ImportError::VersionUnsupported,
            ),
            (
                serde_json::json!({"format":"PMX1","version":2,"entries":[{}]}),
                ImportError::VersionUnsupported,
            ),
            (
                serde_json::json!({"format":"PMX1","version":1}),
                ImportError::EntriesRequired,
            ),
            (
                serde_json::json!({"format":"PMX1","version":1,"entries":[]}),
                ImportError::NothingToImport,
            ),
            (
                serde_json::json!({"format":"PMX1","version":1,"entries":[{},{},{},{},{}]}),
                ImportError::BatchTooLarge,
            ),
            (
                serde_json::json!({"format":"PMX1","version":1,"entries":["x"]}),
                ImportError::EntryNotAnObject,
            ),
            (
                serde_json::json!({"format":"PMX1","version":1,"entries":[{"title":5}]}),
                ImportError::FieldTooLongOrNotString,
            ),
            (
                serde_json::json!({"format":"PMX1","version":1,"entries":[{"totp":"short"}]}),
                ImportError::TotpSecretInvalid,
            ),
        ];
        for (doc, want) in cases {
            assert_eq!(parse_import(&doc).unwrap_err(), want, "doc={doc}");
        }
    }

    #[test]
    fn import_rejects_oversize_field() {
        let big = "A".repeat(ENTRY_TITLE);
        let doc = serde_json::json!({
            "format": "PMX1",
            "version": 1,
            "entries": [{"title": big}],
        });
        assert_eq!(
            parse_import(&doc).unwrap_err(),
            ImportError::FieldTooLongOrNotString
        );
        // Exactly capacity - 1 is allowed.
        let ok = "A".repeat(ENTRY_TITLE - 1);
        let doc = serde_json::json!({
            "format": "PMX1",
            "version": 1,
            "entries": [{"title": ok}],
        });
        assert_eq!(
            parse_import(&doc).unwrap()[0].get(Field::Title).len(),
            ENTRY_TITLE - 1
        );
    }

    #[test]
    fn note_field_capacity_matches_entry() {
        assert_eq!(ENTRY_NOTE, 400);
    }

    #[test]
    fn parse_import_bytes_bad_json() {
        assert_eq!(
            parse_import_bytes(b"{not json").unwrap_err(),
            ImportError::FormatRequired
        );
    }

    #[test]
    fn import_error_codes_are_the_wire_strings() {
        // The HTTP layer returns these verbatim; the C++ handler used the same
        // spellings, so they are a compatibility contract.
        let cases = [
            (ImportError::FormatRequired, "format_required"),
            (ImportError::VersionUnsupported, "version_unsupported"),
            (ImportError::EntriesRequired, "entries_required"),
            (ImportError::NothingToImport, "nothing_to_import"),
            (ImportError::BatchTooLarge, "batch_too_large"),
            (ImportError::EntryNotAnObject, "entry_not_an_object"),
            (
                ImportError::FieldTooLongOrNotString,
                "field_too_long_or_not_a_string",
            ),
            (ImportError::TotpSecretInvalid, "totp_secret_invalid"),
            (ImportError::TotpParamsInvalid, "totp_params_invalid"),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code);
            assert_eq!(err.to_string(), code);
        }
    }

    #[test]
    fn parse_import_bytes_accepts_a_valid_document() {
        let doc = br#"{"format":"PMX1","version":1,"entries":[{"title":"T"}]}"#;
        let entries = parse_import_bytes(doc).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].get_str(Field::Title).unwrap(), "T");
    }

    #[test]
    fn export_head_and_tail_frame_the_document() {
        let head = export_head(3);
        assert_eq!(
            head,
            "{\"ok\":true,\"format\":\"PMX1\",\"version\":1,\"count\":3,\"entries\":["
        );
        assert_eq!(EXPORT_TAIL, "]}");
        // The streamed form and the assembled form must agree.
        let e = sample();
        let mut streamed = export_head(1);
        streamed.push_str(&encode_entry(&e));
        streamed.push_str(EXPORT_TAIL);
        assert_eq!(streamed, export_document(&[e]));
    }

    #[test]
    fn an_empty_export_is_a_valid_document() {
        let doc = export_document(&[]);
        assert_eq!(
            doc,
            "{\"ok\":true,\"format\":\"PMX1\",\"version\":1,\"count\":0,\"entries\":[]}"
        );
        let value: Value = serde_json::from_str(&doc).unwrap();
        // An empty document is refused on import: it would silently wipe
        // nothing while claiming success.
        assert_eq!(
            parse_import(&value).unwrap_err(),
            ImportError::NothingToImport
        );
    }

    #[test]
    fn into_entry_starts_from_id_zero() {
        // The id is assigned by the vault on import, so a restore into another
        // device never reuses foreign ids.
        let p = Pmx1Entry {
            title: "T".into(),
            login: "L".into(),
            password: "P".into(),
            url: "U".into(),
            note: "N".into(),
            tags: "g".into(),
            totp: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            totp_digits: "8".into(),
            totp_period: "60".into(),
        };
        let e = p.into_entry();
        assert_eq!(e.id, 0);
        assert_eq!(e.get_str(Field::Title).unwrap(), "T");
        assert_eq!(e.get_str(Field::TotpDigits).unwrap(), "8");
        assert_eq!(e.get_str(Field::TotpPeriod).unwrap(), "60");
    }

    #[test]
    fn from_entry_and_into_entry_round_trip() {
        let e = sample();
        let back = Pmx1Entry::from_entry(&e).into_entry();
        assert_eq!(back.get_str(Field::Title).unwrap(), "Mail");
        assert_eq!(back.get_str(Field::Login).unwrap(), "user@example.com");
        assert_eq!(back.get_str(Field::Password).unwrap(), "hunter2");
        assert_eq!(
            back.get_str(Field::Url).unwrap(),
            "https://mail.example.com"
        );
        assert_eq!(back.get_str(Field::Note).unwrap(), "primary");
        assert_eq!(back.get_str(Field::Tags).unwrap(), "work");
        assert_eq!(
            back.get_str(Field::Totp).unwrap(),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(back.get_str(Field::TotpDigits).unwrap(), "8");
        assert_eq!(back.get_str(Field::TotpPeriod).unwrap(), "60");
    }

    #[test]
    fn a_null_totp_is_an_empty_totp() {
        // `null` means "empty", not "invalid": a document written by an older
        // exporter must still import.
        let doc: Value = serde_json::json!({
            "format": "PMX1",
            "version": 1,
            "entries": [{"title": "T", "totp": null}],
        });
        let back = parse_import(&doc).unwrap();
        assert!(back[0].get(Field::Totp).is_empty());
    }
}
