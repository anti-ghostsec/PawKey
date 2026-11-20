//! Codes: TOTP (RFC 6238) on top of HOTP (RFC 4226), base32 secrets, and
//! the `otpauth://totp/...` links that setup QR codes hold.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Algo {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algo {
    pub fn parse(s: &str) -> Option<Algo> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Some(Algo::Sha1),
            "SHA256" => Some(Algo::Sha256),
            "SHA512" => Some(Algo::Sha512),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Account {
    pub issuer: String,
    pub name: String,
    /// Normalised base32 secret (upper case, no padding/spaces).
    pub secret: String,
    pub digits: u32,
    pub period: u64,
    #[zeroize(skip)]
    pub algo: Algo,
    /// Random, made once: how devices that sync tell accounts apart.
    #[serde(default)]
    pub uid: String,
}

/// 128 random bits, as hex.
pub fn new_uid() -> String {
    let mut b = [0u8; 16];
    vaultkit::random_bytes(&mut b).expect("no OS randomness");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Account {
    pub fn new(issuer: &str, name: &str, secret: &str) -> Result<Account, String> {
        let secret = normalize_base32(secret);
        let bytes = base32_decode(&secret).ok_or("Secret is not valid base32")?;
        if bytes.is_empty() {
            return Err("Secret is empty".into());
        }
        Ok(Account {
            issuer: issuer.trim().to_string(),
            name: name.trim().to_string(),
            secret,
            digits: 6,
            period: 30,
            algo: Algo::Sha1,
            uid: new_uid(),
        })
    }

    pub fn code_at(&self, unix_time: u64) -> String {
        let mut key = base32_decode(&self.secret).unwrap_or_default();
        let code = hotp(&key, unix_time / self.period, self.digits, self.algo);
        key.zeroize();
        code
    }

    /// What the list shows: the issuer, or the account name when there's none.
    pub fn title(&self) -> &str {
        if self.issuer.is_empty() {
            &self.name
        } else {
            &self.issuer
        }
    }

    /// Seconds left before the current code expires.
    pub fn remaining(&self, unix_time: u64) -> u64 {
        self.period - (unix_time % self.period)
    }
}

pub fn hotp(key: &[u8], counter: u64, digits: u32, algo: Algo) -> String {
    let msg = counter.to_be_bytes();
    let mac: Vec<u8> = match algo {
        Algo::Sha1 => mac_bytes::<Hmac<sha1::Sha1>>(key, &msg),
        Algo::Sha256 => mac_bytes::<Hmac<sha2::Sha256>>(key, &msg),
        Algo::Sha512 => mac_bytes::<Hmac<sha2::Sha512>>(key, &msg),
    };
    let off = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([mac[off] & 0x7f, mac[off + 1], mac[off + 2], mac[off + 3]]);
    let code = bin as u64 % 10u64.pow(digits);
    format!("{:0width$}", code, width = digits as usize)
}

fn mac_bytes<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

pub fn normalize_base32(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '=').map(|c| c.to_ascii_uppercase()).collect()
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in normalize_base32(s).bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        } as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse an `otpauth://totp/Issuer:account?secret=...` URI (as encoded in setup QR codes).
pub fn parse_otpauth(uri: &str) -> Result<Account, String> {
    let rest = uri.trim().strip_prefix("otpauth://").ok_or("URI must start with otpauth://")?;
    let (kind, rest) = rest.split_once('/').ok_or("Malformed otpauth URI")?;
    if !kind.eq_ignore_ascii_case("totp") {
        return Err("Only TOTP (time-based) accounts are supported".into());
    }
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode(label);
    let (mut issuer, name) = match label.split_once(':') {
        Some((i, n)) => (i.trim().to_string(), n.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };

    let (mut secret, mut digits, mut period, mut algo) = (None, 6u32, 30u64, Algo::Sha1);
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(v),
            "issuer" => issuer = v,
            "digits" => digits = v.parse().map_err(|_| "Bad digits value")?,
            "period" => period = v.parse().map_err(|_| "Bad period value")?,
            "algorithm" => algo = Algo::parse(&v).ok_or("Unsupported algorithm")?,
            _ => {}
        }
    }
    if !(6..=8).contains(&digits) {
        return Err("Digits must be 6, 7 or 8".into());
    }
    if period == 0 {
        return Err("Period must be positive".into());
    }
    let mut acc = Account::new(&issuer, &name, &secret.ok_or("URI has no secret")?)?;
    acc.digits = digits;
    acc.period = period;
    acc.algo = algo;
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (8 digits).
    #[test]
    fn rfc6238_vectors() {
        let k1 = b"12345678901234567890";
        let k256 = b"12345678901234567890123456789012";
        let k512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, s1, s256, s512) in cases {
            assert_eq!(hotp(k1, t / 30, 8, Algo::Sha1), s1, "sha1 t={t}");
            assert_eq!(hotp(k256, t / 30, 8, Algo::Sha256), s256, "sha256 t={t}");
            assert_eq!(hotp(k512, t / 30, 8, Algo::Sha512), s512, "sha512 t={t}");
        }
    }

    // RFC 4226 Appendix D.
    #[test]
    fn rfc4226_vectors() {
        let expect = ["755224", "287082", "359152", "969429", "338314"];
        for (i, e) in expect.iter().enumerate() {
            assert_eq!(hotp(b"12345678901234567890", i as u64, 6, Algo::Sha1), *e);
        }
    }

    #[test]
    fn base32() {
        assert_eq!(base32_decode("GEZDGNBVGY3TQOJQ").unwrap(), b"1234567890");
        assert_eq!(base32_decode("gezd gnbv gy3t qojq").unwrap(), b"1234567890");
        assert!(base32_decode("GEZ1").is_none());
    }

    #[test]
    fn otpauth() {
        let a = parse_otpauth(
            "otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
        )
        .unwrap();
        assert_eq!(a.issuer, "ACME Co");
        assert_eq!(a.name, "john@example.com");
        assert_eq!(a.digits, 6);
        assert!(parse_otpauth("otpauth://hotp/x?secret=AAAA").is_err());
        assert!(parse_otpauth("otpauth://totp/x").is_err());
    }
}
