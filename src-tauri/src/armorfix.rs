//! Whitespace-tolerant armor handling.
//!
//! Chat apps, mail clients and web editors routinely mangle ASCII armor:
//! they re-wrap base64 lines at odd widths, collapse or multiply blank
//! lines, strip trailing spaces into nothing, or paste the whole block as
//! one long line. rPGP's dearmorer copes with some of this, but not all.
//!
//! `normalize_armor` re-canonicalizes a pasted block before parsing:
//! - finds the first "-----BEGIN ...-----" line (case-tolerant),
//! - keeps armor headers (lines with a colon before any base64 body),
//! - strips ALL whitespace from the body and re-wraps base64 at 64 columns,
//! - preserves the trailing CRC24 checksum line when present,
//! - reattaches the matching "-----END ...-----" footer.
//!
//! If the input is not armored at all, it is returned unchanged (the caller
//! decides what to do with plain text / binary-base64 input).

/// The armor block type a pasted string appears to contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffedKind {
    Message,
    Cleartext,
    PublicKey,
    PrivateKey,
    DetachedSignature,
    NotArmored,
}

/// Cheap, allocation-light sniff of the first armor header in `input`.
pub fn sniff(input: &str) -> SniffedKind {
    let upper = input.to_ascii_uppercase();
    if upper.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
        SniffedKind::Cleartext
    } else if upper.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        SniffedKind::PrivateKey
    } else if upper.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        SniffedKind::PublicKey
    } else if upper.contains("-----BEGIN PGP SIGNATURE-----") {
        SniffedKind::DetachedSignature
    } else if upper.contains("-----BEGIN PGP MESSAGE-----") {
        SniffedKind::Message
    } else {
        SniffedKind::NotArmored
    }
}

/// Canonicalize mangled armor so rPGP's parser always sees well-formed input.
/// Non-armored input is returned as-is.
pub fn normalize_armor(input: &str) -> String {
    if sniff(input) == SniffedKind::NotArmored || sniff(input) == SniffedKind::Cleartext {
        // Cleartext framework messages must NOT be rewritten: the signed text
        // between the headers is part of the signature. rPGP's cleartext
        // parser tolerates the usual whitespace damage on its own.
        return input.to_string();
    }

    let lines: Vec<&str> = input.lines().collect();
    let begin_idx = match lines.iter().position(|l| l.trim_start().to_ascii_uppercase().starts_with("-----BEGIN ")) {
        Some(i) => i,
        None => return input.to_string(),
    };

    let begin_line = lines[begin_idx].trim().to_string();
    let block_kind = begin_line
        .trim_start_matches('-')
        .trim_start()
        .to_ascii_uppercase();

    // Collect everything until the matching END line.
    let mut headers: Vec<String> = Vec::new();
    let mut body: String = String::new();
    let mut checksum: Option<String> = None;
    let mut end_line: Option<String> = None;
    let mut in_body = false;

    for line in lines.iter().skip(begin_idx + 1) {
        let t = line.trim();
        if t.to_ascii_uppercase().starts_with("-----END ") {
            end_line = Some(t.to_string());
            break;
        }
        if !in_body {
            if t.is_empty() {
                // Blank line between headers and body (possibly mangled away
                // by an editor): if the next non-empty line looks like base64
                // we can't know - just switch to body mode.
                continue;
            }
            if t.contains(':') && !looks_like_base64(t) {
                headers.push(t.to_string());
                continue;
            }
            in_body = true;
        }
        // Body line: strip every whitespace char. The CRC24 checksum line
        // may have been merged into the body by re-wrapping - it is split
        // off again after the loop (the last '=' run in the stream).
        let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.is_empty() {
            continue;
        }
        body.push_str(&compact);
    }

    let end_line = end_line.unwrap_or_else(|| format!("-----END {block_kind} -----"));

    // Recover a CRC24 checksum that chat-app re-wrapping merged into the
    // body: base64 never contains '=' except as trailing padding, and the
    // checksum is the final 4-5 chars starting with '='.
    if checksum.is_none() {
        if let Some(pos) = body.rfind('=') {
            let tail_len = body.len() - pos;
            if tail_len <= 5 && pos > 0 && body[pos + 1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/') {
                checksum = Some(body[pos..].to_string());
                body.truncate(pos);
            }
        }
    }

    let mut out = String::with_capacity(input.len() + 64);
    out.push_str(&begin_line);
    out.push('\n');
    for h in &headers {
        out.push_str(h);
        out.push('\n');
    }
    out.push('\n');

    // Re-wrap the base64 body at 64 columns.
    const WRAP: usize = 64;
    let bytes = body.as_bytes();
    for (i, ch) in bytes.iter().enumerate() {
        out.push(*ch as char);
        if (i + 1) % WRAP == 0 {
            out.push('\n');
        }
    }
    if !bytes.is_empty() && bytes.len() % WRAP != 0 {
        out.push('\n');
    }
    if let Some(c) = checksum {
        out.push_str(&c);
        out.push('\n');
    }
    out.push_str(&end_line);
    out.push('\n');
    out
}

/// True when a line consists only of base64-ish characters.
fn looks_like_base64(line: &str) -> bool {
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return false;
    }
    compact
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// For binary (non-armored) message input the UI may hand us base64 instead:
/// detect and decode. Returns None when the input does not look like base64.
pub fn maybe_base64_binary(input: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let compact: String = input
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if compact.len() < 16 || !compact.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANGLED: &str = "\
this is some chat noise above the block
   -----BEGIN PGP PUBLIC KEY BLOCK-----\n\
Comment: mangled\n\
\n\
mQINBG   abcdef gh\r\n\
ijk lmnop\r\n\
=ab12\n\
-----END PGP PUBLIC KEY BLOCK-----";

    #[test]
    fn normalizes_mangled_armor() {
        let out = normalize_armor(MANGLED);
        assert!(out.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));
        assert!(out.contains("Comment: mangled\n"));
        // Both mangled body lines are joined and re-wrapped cleanly.
        assert!(out.contains("mQINBGabcdefghijklmnop\n"));
        assert!(out.contains("=ab12\n"));
        assert!(out.ends_with("-----END PGP PUBLIC KEY BLOCK-----\n"));
    }

    #[test]
    fn recovers_checksum_merged_into_body() {
        // A chat app re-wrapped the body so hard that the CRC24 line got
        // fused into the base64 stream mid-line.
        let input = "\
-----BEGIN PGP MESSAGE-----\n\
\n\
aGVsbG8gd29ybGQ=ab12\n\
-----END PGP MESSAGE-----";
        let out = normalize_armor(input);
        assert!(out.contains("aGVsbG8gd29ybGQ\n=ab12\n"), "checksum not split back out: {out}");
    }

    #[test]
    fn leaves_cleartext_alone() {
        let inp = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nhello\n[detached]\n";
        assert_eq!(normalize_armor(inp), inp);
    }

    #[test]
    fn sniffs_kinds() {
        assert_eq!(sniff("-----BEGIN PGP MESSAGE-----"), SniffedKind::Message);
        assert_eq!(sniff("-----begin pgp public key block-----"), SniffedKind::PublicKey);
        assert_eq!(sniff("hello world"), SniffedKind::NotArmored);
    }
}
