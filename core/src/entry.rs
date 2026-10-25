//! Vault entry: the on-disk record and its field model.
//!
//! Ported from the removed C++ reference. The on-disk representation is a row of
//! NUL-terminated fields written back-to-back with a fixed order:
//! `title, login, password, url, note, tags, totp, totpDigits, totpPeriod`. The
//! fixed capacities below are part of the format; `config::MAX_ENTRY_LEN` (1280)
//! bounds the serialized record.
//!
//! `tags`/`totp` were added in v0.2.0, `totpDigits`/`totpPeriod` afterwards.
//! Fields are positional, and [`Entry::deserialize`] stops when the payload runs
//! out and leaves the tail fields zeroed, so records written by older firmware
//! read back with the missing tail fields empty. An empty `totpDigits`/`totpPeriod`
//! means "use the default profile" (6 digits, 30 s).

/// `title` capacity, including the NUL terminator.
pub const ENTRY_TITLE: usize = 48;
/// `login` capacity, including the NUL terminator.
pub const ENTRY_LOGIN: usize = 96;
/// `password` capacity, including the NUL terminator.
pub const ENTRY_PASSWORD: usize = 160;
/// `url` capacity, including the NUL terminator.
pub const ENTRY_URL: usize = 192;
/// `note` capacity, including the NUL terminator.
pub const ENTRY_NOTE: usize = 400;
/// `tags` capacity, including the NUL terminator (v0.2.0+).
pub const ENTRY_TAGS: usize = 128;
/// `totp` capacity, including the NUL terminator (v0.2.0+).
pub const ENTRY_TOTP: usize = 64;
/// `totpDigits` capacity, including the NUL terminator (decimal ASCII).
pub const ENTRY_TOTP_DIGITS: usize = 4;
/// `totpPeriod` capacity, including the NUL terminator (decimal ASCII seconds).
pub const ENTRY_TOTP_PERIOD: usize = 8;

/// Number of serialized fields, in on-disk order.
pub const ENTRY_FIELDS: usize = 9;

/// Largest payload `serialize` can emit.
pub const ENTRY_PAYLOAD_MAX: usize = ENTRY_TITLE
    + ENTRY_LOGIN
    + ENTRY_PASSWORD
    + ENTRY_URL
    + ENTRY_NOTE
    + ENTRY_TAGS
    + ENTRY_TOTP
    + ENTRY_TOTP_DIGITS
    + ENTRY_TOTP_PERIOD;

const _: () = assert!(ENTRY_PAYLOAD_MAX == 1100);

/// Field selector for [`Entry::get`] / [`Entry::set`]. `#[repr(u8)]` keeps the
/// discriminant stable for indexing and logging.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Entry title.
    Title = 0,
    /// Login/username.
    Login = 1,
    /// Password or secret.
    Password = 2,
    /// URL.
    Url = 3,
    /// Free-form note.
    Note = 4,
    /// Space-separated tags.
    Tags = 5,
    /// TOTP secret (base32).
    Totp = 6,
    /// TOTP digit count (decimal ASCII; empty = default).
    TotpDigits = 7,
    /// TOTP period in seconds (decimal ASCII; empty = default).
    TotpPeriod = 8,
}

impl core::fmt::Display for Field {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Field::Title => "title",
            Field::Login => "login",
            Field::Password => "password",
            Field::Url => "url",
            Field::Note => "note",
            Field::Tags => "tags",
            Field::Totp => "totp",
            Field::TotpDigits => "totpDigits",
            Field::TotpPeriod => "totpPeriod",
        })
    }
}

/// One vault record. Byte layout matches the C++ `vault::Entry` exactly; `id`
/// is not part of the encrypted payload, it lives in the record header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Record id (not part of the encrypted payload).
    pub id: u32,
    /// Title slot.
    pub title: [u8; ENTRY_TITLE],
    /// Login slot.
    pub login: [u8; ENTRY_LOGIN],
    /// Password slot.
    pub password: [u8; ENTRY_PASSWORD],
    /// URL slot.
    pub url: [u8; ENTRY_URL],
    /// Note slot.
    pub note: [u8; ENTRY_NOTE],
    /// Tags slot.
    pub tags: [u8; ENTRY_TAGS],
    /// TOTP secret slot.
    pub totp: [u8; ENTRY_TOTP],
    /// TOTP digit count slot (decimal ASCII; empty = default).
    pub totp_digits: [u8; ENTRY_TOTP_DIGITS],
    /// TOTP period slot (decimal ASCII seconds; empty = default).
    pub totp_period: [u8; ENTRY_TOTP_PERIOD],
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            id: 0,
            title: [0; ENTRY_TITLE],
            login: [0; ENTRY_LOGIN],
            password: [0; ENTRY_PASSWORD],
            url: [0; ENTRY_URL],
            note: [0; ENTRY_NOTE],
            tags: [0; ENTRY_TAGS],
            totp: [0; ENTRY_TOTP],
            totp_digits: [0; ENTRY_TOTP_DIGITS],
            totp_period: [0; ENTRY_TOTP_PERIOD],
        }
    }
}

impl Entry {
    /// Creates an all-zero entry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Raw fixed-capacity slot for a field.
    #[must_use]
    pub fn raw(&self, field: Field) -> &[u8] {
        match field {
            Field::Title => &self.title,
            Field::Login => &self.login,
            Field::Password => &self.password,
            Field::Url => &self.url,
            Field::Note => &self.note,
            Field::Tags => &self.tags,
            Field::Totp => &self.totp,
            Field::TotpDigits => &self.totp_digits,
            Field::TotpPeriod => &self.totp_period,
        }
    }

    fn raw_mut(&mut self, field: Field) -> &mut [u8] {
        match field {
            Field::Title => &mut self.title,
            Field::Login => &mut self.login,
            Field::Password => &mut self.password,
            Field::Url => &mut self.url,
            Field::Note => &mut self.note,
            Field::Tags => &mut self.tags,
            Field::Totp => &mut self.totp,
            Field::TotpDigits => &mut self.totp_digits,
            Field::TotpPeriod => &mut self.totp_period,
        }
    }

    /// Value bytes of a field, up to the first NUL (the stored string).
    #[must_use]
    pub fn get(&self, field: Field) -> &[u8] {
        let raw = self.raw(field);
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        &raw[..end]
    }

    /// Value of a field as UTF-8. Stored strings come from JSON via HTTP, so
    /// this only fails if the flash was corrupted.
    pub fn get_str(&self, field: Field) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(self.get(field))
    }

    /// Copies `value` into a field, truncating to `cap - 1` bytes and always
    /// NUL-terminating. Mirrors the C++ `fillField` / `setFieldBounded` bounds.
    pub fn set(&mut self, field: Field, value: &[u8]) {
        let raw = self.raw_mut(field);
        let cap = raw.len();
        let n = core::cmp::min(value.len(), cap - 1);
        raw[..n].copy_from_slice(&value[..n]);
        for b in &mut raw[n..] {
            *b = 0;
        }
    }

    /// Serializes all seven fields, NUL-terminated and back-to-back, into
    /// `out`. Returns the payload length, or `None` if it does not fit.
    ///
    /// A field that is not NUL-terminated inside its slot (impossible when
    /// built through [`Entry::set`] or [`Entry::deserialize`]) is bounded at
    /// the last byte so this can never read past the slot.
    pub fn serialize(&self, out: &mut [u8]) -> Option<usize> {
        let mut n = 0usize;
        for &field in &FIELD_ORDER {
            let raw = self.raw(field);
            let len = field_strlen(raw) + 1;
            if n + len > out.len() {
                return None;
            }
            out[n..n + len].copy_from_slice(&raw[..len]);
            n += len;
        }
        Some(n)
    }

    /// Reads `len` payload bytes into an entry with the given `id`.
    ///
    /// Mirrors the C++ `deserialize`: it walks the fields and stops as soon as
    /// the payload runs out, leaving the remaining fields zeroed. Short (legacy
    /// five-field) records therefore read back with empty `tags`/`totp`.
    pub fn deserialize(id: u32, data: &[u8]) -> Entry {
        let mut e = Entry {
            id,
            ..Entry::default()
        };
        let len = data.len();
        let mut pos = 0usize;
        for &field in &FIELD_ORDER {
            if pos >= len {
                break;
            }
            let raw = e.raw_mut(field);
            let cap = raw.len();
            let avail = len - pos;
            let mut copy = 0usize;
            while copy < avail && copy + 1 < cap && data[pos + copy] != 0 {
                copy += 1;
            }
            raw[..copy].copy_from_slice(&data[pos..pos + copy]);
            raw[copy] = 0;
            pos += copy;
            if pos < len && data[pos] == 0 {
                pos += 1;
            }
        }
        e
    }
}

// The lint compares field names verbatim and does not see that
// `totp_digits` is printed as `totpDigits`: the debug output deliberately
// uses the JSON field names and redacts the password slot.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.get_str(Field::Title).unwrap_or(""))
            .field("login", &self.get_str(Field::Login).unwrap_or(""))
            .field("password", &"<redacted>")
            .field("url", &self.get_str(Field::Url).unwrap_or(""))
            .field("note", &self.get_str(Field::Note).unwrap_or(""))
            .field("tags", &self.get_str(Field::Tags).unwrap_or(""))
            .field("totp", &self.get_str(Field::Totp).unwrap_or(""))
            .field("totpDigits", &self.get_str(Field::TotpDigits).unwrap_or(""))
            .field("totpPeriod", &self.get_str(Field::TotpPeriod).unwrap_or(""))
            .finish()
    }
}

/// `(JSON key, vault field)` in import/export order. Single source of truth for
/// the nine entry fields; the binary order is derived from it below.
pub const FIELD_KEYS: &[(&str, Field)] = &[
    ("title", Field::Title),
    ("login", Field::Login),
    ("password", Field::Password),
    ("url", Field::Url),
    ("note", Field::Note),
    ("tags", Field::Tags),
    ("totp", Field::Totp),
    ("totpDigits", Field::TotpDigits),
    ("totpPeriod", Field::TotpPeriod),
];

/// The nine fields in binary record order, derived from [`FIELD_KEYS`].
pub const FIELD_ORDER: [Field; ENTRY_FIELDS] = {
    let mut out = [Field::Title; ENTRY_FIELDS];
    let mut i = 0;
    while i < FIELD_KEYS.len() {
        out[i] = FIELD_KEYS[i].1;
        i += 1;
    }
    out
};
const _: () = assert!(FIELD_KEYS.len() == ENTRY_FIELDS);

/// Length of a stored field string. If the slot has no NUL (should not happen),
/// the last byte is treated as the terminator so callers stay in bounds.
fn field_strlen(raw: &[u8]) -> usize {
    match raw.iter().position(|&b| b == 0) {
        Some(p) => p,
        None => raw.len() - 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Entry {
        let mut e = Entry::new();
        e.id = 7;
        e.set(Field::Title, b"Mail");
        e.set(Field::Login, b"user@example.com");
        e.set(Field::Password, b"hunter2");
        e.set(Field::Url, b"https://mail.example.com");
        e.set(Field::Note, b"primary account");
        e.set(Field::Tags, b"work,email");
        e.set(Field::Totp, b"JBSWY3DPEHPK3PXP");
        e.set(Field::TotpDigits, b"8");
        e.set(Field::TotpPeriod, b"60");
        e
    }

    #[test]
    fn payload_max_is_1100() {
        assert_eq!(ENTRY_PAYLOAD_MAX, 1100);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let e = sample();
        let mut buf = [0u8; ENTRY_PAYLOAD_MAX];
        let n = e.serialize(&mut buf).unwrap();
        // "Mail\0" (5) + 17 + 8 + 25 + 16 + 11 + 17 + "8\0" (2) + "60\0" (3) = 104
        assert_eq!(n, 5 + 17 + 8 + 25 + 16 + 11 + 17 + 2 + 3);
        let back = Entry::deserialize(e.id, &buf[..n]);
        assert_eq!(back, e);
        assert_eq!(back.get_str(Field::Password).unwrap(), "hunter2");
        assert_eq!(back.get_str(Field::TotpDigits).unwrap(), "8");
        assert_eq!(back.get_str(Field::TotpPeriod).unwrap(), "60");
    }

    #[test]
    fn legacy_five_field_record_reads_tail_empty() {
        // A record written before tags/totp/totpDigits/totpPeriod existed.
        let e = sample();
        let mut full = [0u8; ENTRY_PAYLOAD_MAX];
        let n = e.serialize(&mut full).unwrap();
        // Trim the trailing four fields: tags(11) + totp(17) + digits(2) + period(3).
        let legacy = &full[..n - 11 - 17 - 2 - 3];
        let back = Entry::deserialize(3, legacy);
        assert_eq!(back.id, 3);
        assert_eq!(back.get_str(Field::Title).unwrap(), "Mail");
        assert_eq!(back.get_str(Field::Note).unwrap(), "primary account");
        assert!(back.get(Field::Tags).is_empty());
        assert!(back.get(Field::Totp).is_empty());
        assert!(back.get(Field::TotpDigits).is_empty());
        assert!(back.get(Field::TotpPeriod).is_empty());
    }

    #[test]
    fn legacy_seven_field_record_reads_digits_period_empty() {
        // A v0.2.0 record: everything up to `totp`, no digits/period.
        let e = sample();
        let mut full = [0u8; ENTRY_PAYLOAD_MAX];
        let n = e.serialize(&mut full).unwrap();
        let legacy = &full[..n - 2 - 3];
        let back = Entry::deserialize(9, legacy);
        assert_eq!(back.get_str(Field::Totp).unwrap(), "JBSWY3DPEHPK3PXP");
        assert!(back.get(Field::TotpDigits).is_empty());
        assert!(back.get(Field::TotpPeriod).is_empty());
    }

    #[test]
    fn set_truncates_and_terminates() {
        let mut e = Entry::new();
        let long = vec![b'A'; ENTRY_TITLE + 50];
        e.set(Field::Title, &long);
        let raw = e.raw(Field::Title);
        assert_eq!(raw[ENTRY_TITLE - 1], 0);
        assert_eq!(e.get(Field::Title).len(), ENTRY_TITLE - 1);
    }

    #[test]
    fn serialize_rejects_short_buffer() {
        let e = sample();
        let mut small = [0u8; 16];
        assert!(e.serialize(&mut small).is_none());
    }

    #[test]
    fn a_new_entry_is_all_zero() {
        let e = Entry::new();
        assert_eq!(e.id, 0);
        for field in FIELD_ORDER {
            assert!(e.get(field).is_empty(), "{field} is not empty");
        }
    }

    #[test]
    fn field_keys_and_field_order_agree() {
        // FIELD_ORDER is derived from FIELD_KEYS; a mismatch would serialize
        // the fields in a different order than the JSON document lists them.
        assert_eq!(FIELD_KEYS.len(), ENTRY_FIELDS);
        for (i, (_key, field)) in FIELD_KEYS.iter().enumerate() {
            assert_eq!(FIELD_ORDER[i], *field);
        }
        // The JSON key names are the wire contract.
        let keys: Vec<&str> = FIELD_KEYS.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            keys,
            vec![
                "title",
                "login",
                "password",
                "url",
                "note",
                "tags",
                "totp",
                "totpDigits",
                "totpPeriod"
            ]
        );
    }

    #[test]
    fn field_display_matches_the_json_key() {
        for (key, field) in FIELD_KEYS {
            assert_eq!(field.to_string(), *key);
        }
    }

    #[test]
    fn get_str_rejects_invalid_utf8() {
        // The vault stores raw bytes; only the HTTP path guarantees UTF-8.
        // A corrupted slot must be reported, not silently mangled.
        let mut e = Entry::new();
        e.title[0] = 0xFF;
        assert!(e.get_str(Field::Title).is_err());
    }

    #[test]
    fn set_leaves_no_stale_bytes_behind() {
        // Shrinking a field must clear the tail, otherwise a later read would
        // see the remains of the previous value.
        let mut e = Entry::new();
        e.set(Field::Title, b"a-long-title-value");
        e.set(Field::Title, b"short");
        assert_eq!(e.get_str(Field::Title).unwrap(), "short");
        assert!(e.raw(Field::Title)[5..].iter().all(|&b| b == 0));
    }

    #[test]
    fn set_with_an_empty_value_clears_the_field() {
        let mut e = Entry::new();
        e.set(Field::Note, b"something");
        e.set(Field::Note, b"");
        assert!(e.get(Field::Note).is_empty());
    }

    #[test]
    fn serialize_is_exact_and_rejects_a_buffer_one_byte_short() {
        let e = sample();
        let mut buf = [0u8; ENTRY_PAYLOAD_MAX];
        let n = e.serialize(&mut buf).unwrap();
        assert!(e.serialize(&mut buf[..n - 1]).is_none());
        assert!(e.serialize(&mut buf[..n]).is_some());
        // The payload is a sequence of NUL-terminated strings.
        assert_eq!(buf[n - 1], 0);
    }
}
