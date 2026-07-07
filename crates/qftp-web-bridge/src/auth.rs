//! Bearer-token authentication for the WebTransport bridge.
//!
//! Browsers cannot attach arbitrary request headers to a `WebTransport`
//! connection, so the qftp-server mTLS identity primitive is not
//! reachable from the web. The bridge instead carries an opaque bearer
//! token in the connection URL's query string
//! (`https://host:port/?token=...`); the token is read from the
//! WebTransport `:path` pseudo-header when the session is accepted.
//!
//! The token in the query string is percent-decoded (form style: `+`
//! decodes to a space) before it is checked, so tokens may contain any
//! bytes -- base64-style tokens with `+`, `/` and `=` round-trip
//! correctly. Tokens should be high-entropy random strings: they are
//! the only secret gating access over this transport.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use qftp_protocol::user::{User, UserDirectory};
use serde::Deserialize;

// `TokenSpec`, `TokenConfig` and `TokenDirectory` all carry raw bearer
// tokens -- the only secret gating access over this transport (see the
// module doc). They deliberately do *not* derive `Debug`: an
// accidental `{:?}` (a new `tracing` field, an `expect`/panic message,
// or a `Debug` on an enclosing type) would otherwise dump every token
// in plaintext. The manual impls below redact the secrets.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenSpec {
    token: String,
    user: String,
}

impl fmt::Debug for TokenSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSpec")
            .field("token", &"<redacted>")
            .field("user", &"<redacted>")
            .finish()
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenConfig {
    #[serde(default)]
    tokens: Vec<TokenSpec>,
}

impl fmt::Debug for TokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenConfig")
            .field("tokens", &self.tokens.len())
            .finish()
    }
}

/// Maps opaque bearer tokens to configured user names. When the
/// directory is in the disabled state (`anonymous`), token auth is off
/// and every session is served as the anonymous user -- mirroring the
/// qftp-server fallback when no `--users` file is configured.
pub struct TokenDirectory {
    by_token: Option<HashMap<String, String>>,
}

impl fmt::Debug for TokenDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The map keys are raw bearer tokens and the values are user
        // names, so neither is printed. Expose only whether auth is on
        // and, when it is, how many tokens are configured.
        match &self.by_token {
            None => f
                .debug_struct("TokenDirectory")
                .field("auth_enabled", &false)
                .finish(),
            Some(map) => f
                .debug_struct("TokenDirectory")
                .field("auth_enabled", &true)
                .field("tokens", &map.len())
                .finish(),
        }
    }
}

impl TokenDirectory {
    /// Token auth disabled: every session resolves to the anonymous user.
    pub fn anonymous() -> Self {
        Self { by_token: None }
    }

    /// Load a `--users-tokens` TOML file. Every referenced user must
    /// already exist in `users`, so a typo fails fast at startup rather
    /// than silently rejecting every login.
    pub fn load(path: &Path, users: &UserDirectory) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read tokens file: {}", path.display()))?;
        let cfg: TokenConfig = toml::from_str(&text)
            .with_context(|| format!("failed to parse tokens file: {}", path.display()))?;

        let mut by_token = HashMap::new();
        for spec in cfg.tokens {
            if spec.token.is_empty() {
                bail!("tokens file has an empty token for user '{}'", spec.user);
            }
            if users.lookup_strict(&spec.user).is_none() {
                bail!(
                    "tokens file references user '{}' that is not in the users file",
                    spec.user
                );
            }
            if by_token.insert(spec.token, spec.user.clone()).is_some() {
                bail!("duplicate token in tokens file (user '{}')", spec.user);
            }
        }
        Ok(Self {
            by_token: Some(by_token),
        })
    }

    /// Whether token auth is active. When false, sessions are anonymous.
    pub fn auth_enabled(&self) -> bool {
        self.by_token.is_some()
    }

    /// Resolve the user for a WebTransport session from its `:path`
    /// (for example `/?token=abc`). Returns `None` when auth is enabled
    /// and the token is missing or unknown, so the caller refuses the
    /// session. When auth is disabled the anonymous user is returned.
    pub fn resolve(&self, path: &str, users: &UserDirectory) -> Option<Arc<User>> {
        match &self.by_token {
            None => Some(users.anonymous()),
            Some(map) => {
                let token = extract_token(path)?;
                // The token is an authentication secret, so it must not
                // be looked up with `HashMap::get`: that comparison is
                // not constant-time and leaks how many leading bytes a
                // guess got right. Scan every entry instead, comparing
                // each in constant time and never breaking early, so
                // the lookup time is independent of the token's value.
                let mut matched: Option<&String> = None;
                for (known, name) in map {
                    if qftp_common::util::constant_time_eq(token.as_bytes(), known.as_bytes()) {
                        matched = Some(name);
                    }
                }
                users.lookup_strict(matched?)
            }
        }
    }
}

/// Cross-origin admission policy for WebTransport sessions.
///
/// WebTransport is **not** covered by CORS or the same-origin policy:
/// any web page a victim's browser renders can attempt
/// `new WebTransport("https://bridge:4433/...")` against any bridge the
/// victim's machine can reach. With token auth the token is the gate —
/// a hostile page does not know it — but in anonymous mode a drive-by
/// page could silently list and read files from a LAN or localhost
/// bridge. The bridge therefore checks the extended-CONNECT request's
/// `origin` header against an operator-supplied allowlist
/// (`--allowed-origins`) before token resolution.
///
/// Browsers always attach `origin` to the WebTransport CONNECT, so a
/// session *without* one cannot have been initiated by a web page;
/// native/test clients that omit it are judged separately (see
/// [`OriginPolicy::admits`]).
pub enum OriginPolicy {
    /// `--allowed-origins` was not given. Non-browser sessions (no
    /// `origin` header) are admitted; browser sessions are admitted
    /// only when token auth gates them, and refused in anonymous mode
    /// (the drive-by case this policy exists to stop).
    Unconfigured,
    /// `--allowed-origins '*'`: every session is admitted regardless
    /// of origin. An explicit operator opt-out, for deployments that
    /// intend to be a public anonymous read-only endpoint.
    AllowAny,
    /// Explicit allowlist of normalized origins. Only sessions whose
    /// `origin` header matches an entry are admitted; sessions without
    /// an `origin` header are refused (see [`OriginPolicy::admits`]).
    List(Vec<String>),
}

impl OriginPolicy {
    /// Parse the `--allowed-origins` argument: a comma-separated list
    /// of web origins (`scheme://host[:port]`), or the single wildcard
    /// `*`. Entries are normalized (trimmed, lowercased, one trailing
    /// `/` stripped) so `https://App.Example/` matches the
    /// `https://app.example` a browser actually sends.
    pub fn parse(arg: Option<&str>) -> Result<Self> {
        let Some(arg) = arg else {
            return Ok(Self::Unconfigured);
        };
        let raw: Vec<&str> = arg.split(',').map(str::trim).collect();
        if raw.contains(&"*") {
            if raw.len() != 1 {
                bail!("--allowed-origins: '*' cannot be combined with other origins");
            }
            return Ok(Self::AllowAny);
        }
        let mut list = Vec::new();
        for entry in raw {
            if entry.is_empty() {
                bail!("--allowed-origins: empty origin in list");
            }
            if !entry.contains("://") {
                bail!(
                    "--allowed-origins: '{entry}' is not an origin \
                     (expected scheme://host[:port], e.g. https://files.example.com)"
                );
            }
            list.push(normalize_origin(entry));
        }
        Ok(Self::List(list))
    }

    /// Decide whether a session with the given `origin` header may
    /// proceed to authentication. `auth_enabled` is whether bearer-token
    /// auth is active (see [`TokenDirectory::auth_enabled`]).
    ///
    /// * With an explicit allowlist, only a matching `origin` is
    ///   admitted. A session with *no* `origin` header is refused too:
    ///   the operator asked for origin gating, and a header-less dialer
    ///   is not a browser, so it has no business on the browser bridge
    ///   (the native `qftp-server` serves it better and with mTLS).
    /// * Unconfigured: header-less (non-browser) sessions are admitted;
    ///   browser sessions are admitted only when a bearer token still
    ///   gates access, and refused in anonymous mode — a drive-by page
    ///   must not reach an unauthenticated bridge.
    pub fn admits(&self, origin: Option<&str>, auth_enabled: bool) -> bool {
        match self {
            Self::AllowAny => true,
            Self::List(list) => match origin {
                Some(o) => list.contains(&normalize_origin(o)),
                None => false,
            },
            Self::Unconfigured => match origin {
                None => true,
                Some(_) => auth_enabled,
            },
        }
    }
}

/// Normalize an origin string for comparison: trim whitespace, strip
/// one trailing `/`, lowercase. Scheme and host are case-insensitive
/// (RFC 3986); an origin has no path component, so a trailing slash is
/// operator input noise, not meaning.
fn normalize_origin(origin: &str) -> String {
    origin.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Pull the `token` query parameter out of a WebTransport `:path` and
/// percent-decode it.
///
/// The browser SPA puts the token into the URL with
/// `URLSearchParams.set`, which form-encodes the value: a space becomes
/// `+` and any URL-special byte (including a literal `+`) becomes a
/// `%XX` escape. Base64-style tokens routinely contain `+`, `/` and
/// `=`, so the raw query-string slice must be decoded back to its
/// original bytes before it is compared against the configured token,
/// otherwise every such web login fails. Decoding produces an owned
/// `String`, hence the `Option<String>` return type.
fn extract_token(path: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    let raw = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))?;
    // Form encoding (what `URLSearchParams` produces) maps a space to
    // `+`; a literal `+` arrives as `%2B`. Translate `+` back to a
    // space before percent-decoding so the round-trip is exact.
    let space_decoded = raw.replace('+', " ");
    // Reject malformed UTF-8 outright rather than coercing it with
    // U+FFFD: a token is compared byte-for-byte against the configured
    // value, so a lossy decode would only ever produce a non-matching
    // string while masking the fact that the input wasn't a valid
    // token. `decode_utf8` returns `Err` on invalid bytes, which maps
    // cleanly to `None` (no usable token).
    percent_encoding::percent_decode_str(&space_decoded)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qftp_protocol::user::{Permissions, UserConfig, UserSpec};

    #[test]
    fn extract_token_reads_query_param() {
        assert_eq!(extract_token("/?token=abc"), Some("abc".to_string()));
        assert_eq!(
            extract_token("/path?x=1&token=abc&y=2"),
            Some("abc".to_string())
        );
        assert_eq!(extract_token("/?token="), Some(String::new()));
        assert_eq!(extract_token("/no-query"), None);
        assert_eq!(extract_token("/?other=1"), None);
    }

    #[test]
    fn extract_token_percent_decodes_value() {
        // `URLSearchParams.set` form-encodes the token: a base64 token
        // such as `a+b/c=` reaches the bridge as `a%2Bb%2Fc%3D`, and a
        // space arrives as `+`. Both must decode back to the original.
        assert_eq!(
            extract_token("/?token=a%2Bb%2Fc%3D"),
            Some("a+b/c=".to_string())
        );
        assert_eq!(
            extract_token("/?token=one+two"),
            Some("one two".to_string())
        );
    }

    #[test]
    fn extract_token_rejects_invalid_utf8() {
        // `%FF` is not valid UTF-8 on its own. A lossy decode would
        // turn it into U+FFFD and yield `Some`; the strict decode must
        // reject it with `None` so a malformed token never reaches the
        // constant-time comparison as a coerced string (L-2).
        assert_eq!(extract_token("/?token=%FF"), None);
        assert_eq!(extract_token("/?token=good%FFbad"), None);
    }

    #[test]
    fn anonymous_directory_ignores_token() {
        let users = UserDirectory::default_anonymous(Path::new("/tmp"));
        let dir = TokenDirectory::anonymous();
        assert!(!dir.auth_enabled());
        let u = dir.resolve("/no-token-here", &users).unwrap();
        assert_eq!(u.name, "anonymous");
    }

    #[test]
    fn load_rejects_user_not_in_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let users = UserDirectory::default_anonymous(tmp.path());
        let tokens_file = tmp.path().join("tokens.toml");
        std::fs::write(
            &tokens_file,
            "[[tokens]]\ntoken = \"t1\"\nuser = \"ghost\"\n",
        )
        .unwrap();
        let err = TokenDirectory::load(&tokens_file, &users).unwrap_err();
        assert!(err.to_string().contains("ghost"), "unexpected: {err}");
    }

    #[test]
    fn debug_redacts_secrets() {
        // A `{:?}` of any token-bearing type must never leak the raw
        // token or the user name it maps to.
        let spec = TokenSpec {
            token: "super-secret-token".to_string(),
            user: "alice".to_string(),
        };
        let spec_dbg = format!("{spec:?}");
        assert!(!spec_dbg.contains("super-secret-token"), "{spec_dbg}");
        assert!(!spec_dbg.contains("alice"), "{spec_dbg}");

        let cfg = TokenConfig { tokens: vec![spec] };
        let cfg_dbg = format!("{cfg:?}");
        assert!(!cfg_dbg.contains("super-secret-token"), "{cfg_dbg}");
        assert!(!cfg_dbg.contains("alice"), "{cfg_dbg}");
        assert!(
            cfg_dbg.contains('1'),
            "should report the token count: {cfg_dbg}"
        );

        let mut map = HashMap::new();
        map.insert("super-secret-token".to_string(), "alice".to_string());
        let dir = TokenDirectory {
            by_token: Some(map),
        };
        let dir_dbg = format!("{dir:?}");
        assert!(!dir_dbg.contains("super-secret-token"), "{dir_dbg}");
        assert!(!dir_dbg.contains("alice"), "{dir_dbg}");
        assert!(dir_dbg.contains("auth_enabled"), "{dir_dbg}");

        let anon_dbg = format!("{:?}", TokenDirectory::anonymous());
        assert!(anon_dbg.contains("false"), "{anon_dbg}");
    }

    #[test]
    fn origin_policy_unconfigured_blocks_browsers_in_anonymous_mode() {
        let p = OriginPolicy::parse(None).unwrap();
        // Non-browser dialers (no `origin` header) are always admitted.
        assert!(p.admits(None, false));
        assert!(p.admits(None, true));
        // Browser sessions: admitted only when a token still gates
        // access. In anonymous mode a drive-by page must be refused.
        assert!(p.admits(Some("https://app.example"), true));
        assert!(!p.admits(Some("https://evil.example"), false));
    }

    #[test]
    fn origin_policy_list_matches_normalized() {
        let p = OriginPolicy::parse(Some("https://App.Example/, http://lan.box:8080")).unwrap();
        assert!(p.admits(Some("https://app.example"), false));
        assert!(p.admits(Some("HTTPS://APP.EXAMPLE"), true));
        assert!(p.admits(Some("http://lan.box:8080"), false));
        assert!(!p.admits(Some("https://evil.example"), true));
        // Same host, different port / scheme are different origins.
        assert!(!p.admits(Some("http://lan.box:9090"), false));
        assert!(!p.admits(Some("https://lan.box:8080"), false));
        // With an explicit allowlist, header-less dialers are refused.
        assert!(!p.admits(None, true));
        assert!(!p.admits(None, false));
    }

    #[test]
    fn origin_policy_wildcard_admits_everything() {
        let p = OriginPolicy::parse(Some("*")).unwrap();
        assert!(p.admits(None, false));
        assert!(p.admits(Some("https://anything.example"), false));
    }

    #[test]
    fn origin_policy_rejects_bad_args() {
        // '*' mixed with explicit origins is a configuration error.
        assert!(OriginPolicy::parse(Some("*, https://a.example")).is_err());
        // Empty entries and non-origin strings are refused.
        assert!(OriginPolicy::parse(Some("https://a.example,,https://b.example")).is_err());
        assert!(OriginPolicy::parse(Some("files.example.com")).is_err());
    }

    #[test]
    fn resolve_maps_token_to_configured_user() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = UserConfig {
            anonymous: None,
            users: vec![UserSpec {
                name: "alice".to_string(),
                home: None,
                permissions: Permissions::read_only(),
                quota_bytes: None,
            }],
        };
        let users = UserDirectory::from_config(tmp.path(), cfg).unwrap();
        let tokens_file = tmp.path().join("tokens.toml");
        std::fs::write(
            &tokens_file,
            "[[tokens]]\ntoken = \"s3cret\"\nuser = \"alice\"\n",
        )
        .unwrap();
        let dir = TokenDirectory::load(&tokens_file, &users).unwrap();
        assert!(dir.auth_enabled());
        assert_eq!(dir.resolve("/?token=s3cret", &users).unwrap().name, "alice");
        assert!(dir.resolve("/?token=wrong", &users).is_none());
        assert!(dir.resolve("/no-token", &users).is_none());
    }
}
