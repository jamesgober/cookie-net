//! Budgets for reading a `Cookie` header: [`Limits`] and [`ValueMode`].

/// How strictly cookie values are read.
///
/// # Examples
///
/// ```
/// use cookie_net::{Cookies, Limits, ValueMode};
///
/// let h = r#"consent={"ads":false}; sid=abc"#;
/// assert_eq!(Cookies::new(h).get("consent"), None);   // strict: skipped and counted
/// let lenient = Cookies::with_limits(h, &Limits::DEFAULT.value_mode(ValueMode::Lenient))?;
/// assert_eq!(lenient.get("consent"), Some(r#"{"ads":false}"#));
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum ValueMode {
    /// `*cookie-octet`, or `DQUOTE *cookie-octet DQUOTE` (rfc6265bis section
    /// 4.2.1). The default: cookie-net's own cookies always fit.
    #[default]
    Strict,
    /// Any byte except a control (HTAB is allowed) and `;`, as long as the
    /// value is valid UTF-8. Matches what user agents store when scripts write
    /// JSON or spaces into `document.cookie`. Names stay strict.
    Lenient,
}

/// Budgets for reading a `Cookie` header, each checked before the work it
/// governs.
///
/// Setters are `const` and bring a value outside their range to the nearest
/// end of it; the getters show what is in force. Whatever the settings, a
/// pair with more than 4096 bytes of name and value is never accepted
/// (rfc6265bis section 5.6).
///
/// # Examples
///
/// ```
/// use cookie_net::{Cookies, Limits};
///
/// const SMALL: Limits = Limits::DEFAULT.max_header_len(4096).max_pairs(16);
/// let cookies = Cookies::with_limits("a=1; b=2", &SMALL)?;
/// assert_eq!(cookies.iter().count(), 2);
/// assert_eq!(Limits::DEFAULT.max_pairs(5000).pairs(), 1024);
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    header_len: usize,
    pairs: u16,
    name_len: u16,
    value_len: u16,
    mode: ValueMode,
}

/// The largest `max_header_len`.
const HEADER_LEN_MAX: usize = 65_536;
/// The largest `max_pairs`.
const PAIRS_MAX: u16 = 1_024;
/// The rfc6265bis name-plus-value limit, also the largest name or value.
pub(crate) const PAIR_MAX: usize = 4_096;

impl Limits {
    /// The defaults: 8,192 header bytes, 64 pairs, 256-byte names, 4,096-byte
    /// values, strict values.
    pub const DEFAULT: Limits = Limits {
        header_len: 8_192,
        pairs: 64,
        name_len: 256,
        value_len: 4_096,
        mode: ValueMode::Strict,
    };

    /// The defaults, as [`Limits::DEFAULT`].
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Limits::new(), cookie_net::Limits::DEFAULT);
    /// ```
    #[must_use]
    pub const fn new() -> Limits {
        Self::DEFAULT
    }

    /// The most bytes a header may have, all field lines together (1 to
    /// 65,536; default 8,192). A longer header is refused before any scan.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{CookieError, Cookies, Limits};
    ///
    /// let tiny = Limits::DEFAULT.max_header_len(4);
    /// assert_eq!(Cookies::with_limits("a=123", &tiny).unwrap_err(), CookieError::HeaderTooLong);
    /// ```
    #[must_use]
    pub const fn max_header_len(self, bytes: usize) -> Limits {
        let bytes = if bytes == 0 {
            1
        } else if bytes > HEADER_LEN_MAX {
            HEADER_LEN_MAX
        } else {
            bytes
        };
        Self {
            header_len: bytes,
            ..self
        }
    }

    /// The most pairs read (1 to 1,024; default 64). One more accepted pair
    /// stops the scan and marks it truncated.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Cookies, Limits};
    ///
    /// let c = Cookies::with_limits("a=1; b=2; c=3", &Limits::DEFAULT.max_pairs(2))?;
    /// assert_eq!(c.iter().count(), 2);
    /// assert!(c.stats().truncated);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn max_pairs(self, n: u16) -> Limits {
        let n = if n == 0 {
            1
        } else if n > PAIRS_MAX {
            PAIRS_MAX
        } else {
            n
        };
        Self { pairs: n, ..self }
    }

    /// The longest name accepted (1 to 4,096; default 256). Longer pairs are
    /// skipped and counted.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Cookies, Limits};
    ///
    /// let c = Cookies::with_limits("abc=1; ab=2", &Limits::DEFAULT.max_name_len(2))?;
    /// assert_eq!(c.get("abc"), None);
    /// assert_eq!(c.get("ab"), Some("2"));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn max_name_len(self, bytes: u16) -> Limits {
        let bytes = if bytes == 0 {
            1
        } else if bytes as usize > PAIR_MAX {
            PAIR_MAX as u16
        } else {
            bytes
        };
        Self {
            name_len: bytes,
            ..self
        }
    }

    /// The longest value accepted (0 to 4,096; default 4,096). Longer pairs
    /// are skipped and counted.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Cookies, Limits};
    ///
    /// let c = Cookies::with_limits("a=123; b=12", &Limits::DEFAULT.max_value_len(2))?;
    /// assert_eq!((c.get("a"), c.get("b")), (None, Some("12")));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn max_value_len(self, bytes: u16) -> Limits {
        let bytes = if bytes as usize > PAIR_MAX {
            PAIR_MAX as u16
        } else {
            bytes
        };
        Self {
            value_len: bytes,
            ..self
        }
    }

    /// How values are read (default [`ValueMode::Strict`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Limits, ValueMode};
    ///
    /// assert_eq!(Limits::DEFAULT.value_mode(ValueMode::Lenient).mode(), ValueMode::Lenient);
    /// ```
    #[must_use]
    pub const fn value_mode(self, mode: ValueMode) -> Limits {
        Self { mode, ..self }
    }

    /// The header length limit in force.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Limits::DEFAULT.header_len(), 8192);
    /// ```
    #[must_use]
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// The pair limit in force.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Limits::DEFAULT.pairs(), 64);
    /// ```
    #[must_use]
    pub const fn pairs(&self) -> u16 {
        self.pairs
    }

    /// The name length limit in force.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Limits::DEFAULT.name_len(), 256);
    /// ```
    #[must_use]
    pub const fn name_len(&self) -> u16 {
        self.name_len
    }

    /// The value length limit in force.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Limits::DEFAULT.value_len(), 4096);
    /// ```
    #[must_use]
    pub const fn value_len(&self) -> u16 {
        self.value_len
    }

    /// The value mode in force.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Limits::DEFAULT.mode(), cookie_net::ValueMode::Strict);
    /// ```
    #[must_use]
    pub const fn mode(&self) -> ValueMode {
        self.mode
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limits_default_values() {
        let l = Limits::default();
        assert_eq!(
            (l.header_len(), l.pairs(), l.name_len(), l.value_len()),
            (8192, 64, 256, 4096)
        );
        assert_eq!(l.mode(), ValueMode::Strict);
        assert_eq!(Limits::new(), l);
    }

    #[test]
    fn test_limits_setters_clamp_at_both_ends() {
        let l = Limits::DEFAULT;
        assert_eq!(l.max_header_len(0).header_len(), 1);
        assert_eq!(l.max_header_len(1).header_len(), 1);
        assert_eq!(l.max_header_len(65_536).header_len(), 65_536);
        assert_eq!(l.max_header_len(65_537).header_len(), 65_536);
        assert_eq!(l.max_pairs(0).pairs(), 1);
        assert_eq!(l.max_pairs(1024).pairs(), 1024);
        assert_eq!(l.max_pairs(1025).pairs(), 1024);
        assert_eq!(l.max_name_len(0).name_len(), 1);
        assert_eq!(l.max_name_len(4097).name_len(), 4096);
        assert_eq!(l.max_value_len(0).value_len(), 0);
        assert_eq!(l.max_value_len(4097).value_len(), 4096);
    }

    #[test]
    fn test_limits_setters_keep_other_fields() {
        let l = Limits::DEFAULT
            .max_pairs(3)
            .value_mode(ValueMode::Lenient)
            .max_name_len(9);
        assert_eq!(
            (l.pairs(), l.name_len(), l.mode()),
            (3, 9, ValueMode::Lenient)
        );
        assert_eq!(l.header_len(), 8192);
    }
}
