//! The cookie-date algorithm (RFC 6265 section 5.1.1, unchanged in
//! rfc6265bis): lenient on purpose, because user agents accept the many date
//! forms servers send in `Expires`. It is different from HTTP-date and has no
//! other consumer, so it lives here (parse-net decision D-020).

use parse_net::date::{days_from_civil, days_in_month};

/// The Unix time of a cookie date, or `None` when the algorithm fails.
///
/// Tokens are split on delimiters; the first token that matches a time
/// (`hh:mm:ss`), then a day of month, a month name, and a year is used, in
/// that order of precedence. Two-digit years 70 to 99 add 1900 and 0 to 69
/// add 2000. Years before 1601, days past the end of the month, and times out
/// of range fail. The result can be before 1970, so it is `i64`.
///
/// # Examples
///
/// ```
/// use cookie_net::cookie_date;
///
/// assert_eq!(cookie_date("Wed, 09 Jun 2021 10:18:14 GMT"), Some(1_623_233_894));
/// assert_eq!(cookie_date("09-Jun-21 10:18:14"), Some(1_623_233_894));
/// assert_eq!(cookie_date("Jun 9 2021 10:18"), None);   // no seconds: the time token does not match
/// assert_eq!(cookie_date("Wed, 09 Jun 1600 10:18:14 GMT"), None);
/// ```
#[must_use]
pub fn cookie_date<V: AsRef<[u8]> + ?Sized>(value: &V) -> Option<i64> {
    let mut time: Option<(u8, u8, u8)> = None;
    let mut day: Option<u8> = None;
    let mut month: Option<u8> = None;
    let mut year: Option<u32> = None;
    for token in value
        .as_ref()
        .split(|&b| is_delimiter(b))
        .filter(|t| !t.is_empty())
    {
        if time.is_none() {
            if let Some(t) = hms(token) {
                time = Some(t);
                continue;
            }
        }
        if day.is_none() {
            if let Some((d, _)) = digits(token, 1, 2) {
                day = u8::try_from(d).ok();
                continue;
            }
        }
        if month.is_none() {
            if let Some(m) = month_of(token) {
                month = Some(m);
                continue;
            }
        }
        if year.is_none() {
            if let Some((y, _)) = digits(token, 2, 4) {
                year = Some(y);
                continue;
            }
        }
    }
    let (hour, minute, second) = time?;
    let (day, month, mut year) = (day?, month?, year?);
    if (70..=99).contains(&year) {
        year += 1900;
    } else if year <= 69 {
        year += 2000;
    }
    if year < 1601 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let year = i32::try_from(year).ok()?;
    if day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))
}

/// `delimiter = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E`.
const fn is_delimiter(b: u8) -> bool {
    matches!(b, 0x09 | 0x20..=0x2f | 0x3b..=0x40 | 0x5b..=0x60 | 0x7b..=0x7e)
}

/// `min` to `max` leading digits followed by nothing or a non-digit
/// (`1*2DIGIT ( non-digit *OCTET )`); the value and the digit count.
fn digits(token: &[u8], min: usize, max: usize) -> Option<(u32, usize)> {
    let n = token.iter().take_while(|b| b.is_ascii_digit()).count();
    if n < min || n > max {
        return None;
    }
    let v = token
        .get(..n)?
        .iter()
        .fold(0u32, |acc, &b| acc * 10 + u32::from(b - b'0'));
    Some((v, n))
}

/// `hms-time ( non-digit *OCTET )`, with `hms-time = time-field ":" time-field
/// ":" time-field` and `time-field = 1*2DIGIT`.
fn hms(token: &[u8]) -> Option<(u8, u8, u8)> {
    let mut rest = token;
    let mut fields = [0u8; 3];
    for (i, field) in fields.iter_mut().enumerate() {
        let n = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if !(1..=2).contains(&n) {
            return None;
        }
        let digits = rest.get(..n)?;
        *field = digits.iter().fold(0u8, |acc, &b| acc * 10 + (b - b'0'));
        rest = rest.get(n..)?;
        if i < 2 {
            rest = rest.strip_prefix(b":")?;
        }
    }
    // after the third field: nothing, or a non-digit and anything
    match rest.first() {
        Some(b) if b.is_ascii_digit() => None,
        _ => Some((fields[0], fields[1], fields[2])),
    }
}

/// A month name: the first three bytes, case-insensitive (`month = ( "jan" /
/// ... / "dec" ) *OCTET`).
fn month_of(token: &[u8]) -> Option<u8> {
    const MONTHS: [&[u8; 3]; 12] = [
        b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov",
        b"dec",
    ];
    let head = token.get(..3)?;
    MONTHS
        .iter()
        .position(|m| head.eq_ignore_ascii_case(&m[..]))
        .and_then(|i| u8::try_from(i + 1).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_623_233_894; // 2021-06-09T10:18:14Z

    #[test]
    fn test_common_forms() {
        assert_eq!(cookie_date("Wed, 09 Jun 2021 10:18:14 GMT"), Some(T));
        assert_eq!(cookie_date("Wednesday, 09-Jun-21 10:18:14 GMT"), Some(T));
        assert_eq!(cookie_date("Wed Jun  9 10:18:14 2021"), Some(T));
        assert_eq!(cookie_date("09 Jun 2021 10:18:14"), Some(T));
        assert_eq!(cookie_date("10:18:14 2021 june 9"), Some(T));
        assert_eq!(cookie_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
    }

    #[test]
    fn test_two_digit_years() {
        assert_eq!(cookie_date("01 Jan 70 00:00:00"), Some(0));
        assert_eq!(
            cookie_date("01 Jan 69 00:00:00"),
            cookie_date("01 Jan 2069 00:00:00")
        );
        assert_eq!(
            cookie_date("01 Jan 99 00:00:00"),
            cookie_date("01 Jan 1999 00:00:00")
        );
        assert_eq!(
            cookie_date("01 Jan 00 00:00:00"),
            cookie_date("01 Jan 2000 00:00:00")
        );
    }

    #[test]
    fn test_failures() {
        assert_eq!(cookie_date(""), None);
        assert_eq!(cookie_date("Jun 9 2021 10:18"), None);
        assert_eq!(cookie_date("09 Jun 1600 10:18:14"), None);
        assert!(cookie_date("01 Jan 1601 00:00:00").is_some());
        assert_eq!(cookie_date("31 Feb 2021 10:18:14"), None);
        assert_eq!(cookie_date("29 Feb 2021 10:18:14"), None);
        assert!(cookie_date("29 Feb 2024 10:18:14").is_some());
        assert_eq!(cookie_date("09 Jun 2021 24:00:00"), None);
        assert_eq!(cookie_date("09 Jun 2021 10:60:00"), None);
        assert_eq!(cookie_date("09 Jun 2021 10:18:60"), None);
        assert_eq!(cookie_date("00 Jun 2021 10:18:14"), None);
        assert_eq!(cookie_date("09 Foo 2021 10:18:14"), None);
        assert_eq!(cookie_date("09 Jun 10:18:14"), None);
    }

    #[test]
    fn test_tokens_and_suffixes() {
        // a time with a non-digit suffix still matches; three digits do not
        assert_eq!(cookie_date("09 Jun 2021 10:18:14Z"), Some(T));
        assert_eq!(cookie_date("09 Jun 2021 100:18:14"), None);
        // day with a suffix, year with five digits is not a year
        assert_eq!(cookie_date("9th Jun 2021 10:18:14"), Some(T));
        assert_eq!(cookie_date("09 Jun 20210 10:18:14"), None);
        // the first matching token wins
        assert_eq!(cookie_date("09 Jun 2021 10:18:14 11:00:00"), Some(T));
        // non-ASCII bytes are non-delimiters and never panic
        assert_eq!(cookie_date(&[0xff, b' ', b'9'][..]), None);
    }

    #[test]
    fn test_hms_parts() {
        assert_eq!(hms(b"1:2:3"), Some((1, 2, 3)));
        assert_eq!(hms(b"01:02:03x"), Some((1, 2, 3)));
        assert_eq!(hms(b"01:02"), None);
        assert_eq!(hms(b"01:02:034"), None);
        assert_eq!(hms(b":02:03"), None);
    }
}
