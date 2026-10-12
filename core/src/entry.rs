//! Vault entry: the on-disk record and its field model.
//!
//! Ported from the removed C++ reference. The on-disk representation is a row of
//! NUL-terminated fields written back-to-back with a fixed order:
//! `title, login, password, url, note, tags, totp`. The fixed capacities below
//! are part of the format: a `static_assert` in the C++ reference pins the payload
//! at 1088 bytes (`sizeof(Entry) - sizeof(id)`), and `config::MAX_ENTRY_LEN`
//! (1280) bounds it.
//!
//! `tags` and `totp` were added in v0.2.0. Records written by older firmware
//! carry only the first five fields; [`Entry::deserialize`] stops when the
//! payload runs out and leaves the tail fields zeroed, so old records read back
//! with empty `tags`/`totp`.

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

/// Number of serialized fields, in on-disk order.
pub const ENTRY_FIELDS: usize = 7;

/// `sizeof(Entry) - sizeof(id)`: the largest payload `serialize` can emit.
pub const ENTRY_PAYLOAD_MAX: usize =
    ENTRY_TITLE + ENTRY_LOGIN + ENTRY_PASSWORD + ENTRY_URL + ENTRY_NOTE + ENTRY_TAGS + ENTRY_TOTP;

const _: () = assert!(ENTRY_PAYLOAD_MAX == 1088);

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
            .finish()
    }
}

/// `(JSON key, vault field)` in import/export order. Single source of truth for
/// the seven entry fields; the binary order is derived from it below.
pub const FIELD_KEYS: &[(&str, Field)] = &[
    ("title", Field::Title),
    ("login", Field::Login),
    ("password", Field::Password),
    ("url", Field::Url),
    ("note", Field::Note),
    ("tags", Field::Tags),
    ("totp", Field::Totp),
];

/// The seven fields in binary record order, derived from [`FIELD_KEYS`].
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
        e
    }

    #[test]
    fn payload_max_is_1088() {
        assert_eq!(ENTRY_PAYLOAD_MAX, 1088);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let e = sample();
        let mut buf = [0u8; ENTRY_PAYLOAD_MAX];
        let n = e.serialize(&mut buf).unwrap();
        // "Mail\0" (5) + 17 + 8 + 25 + 16 + 11 + 17 = 99
        assert_eq!(n, 5 + 17 + 8 + 25 + 16 + 11 + 17);
        let back = Entry::deserialize(e.id, &buf[..n]);
        assert_eq!(back, e);
        assert_eq!(back.get_str(Field::Password).unwrap(), "hunter2");
    }

    #[test]
    fn legacy_five_field_record_reads_tail_empty() {
        // A record written before tags/totp existed.
        let e = sample();
        let mut full = [0u8; ENTRY_PAYLOAD_MAX];
        let n = e.serialize(&mut full).unwrap();
        // Trim the last two fields: name(11) + totp(17) bytes.
        let legacy = &full[..n - 11 - 17];
        let back = Entry::deserialize(3, legacy);
        assert_eq!(back.id, 3);
        assert_eq!(back.get_str(Field::Title).unwrap(), "Mail");
        assert_eq!(back.get_str(Field::Note).unwrap(), "primary account");
        assert!(back.get(Field::Tags).is_empty());
        assert!(back.get(Field::Totp).is_empty());
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
}
