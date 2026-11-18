# PocketPGP <-> GnuPG interop test matrix (plan section 12).
#
# Drives the app's real Rust core through `interop-cli` against stock GnuPG
# in isolated scratch directories. Prints PASS/FAIL per case and exits
# non-zero when anything fails.
#
# Usage:  powershell -File tests\interop.ps1
# Needs:  cargo, gpg >= 2.4 in PATH.
#
# NOTE: PS 5.1 pipes strings to native commands with line-ending rewrites,
# which corrupts armor. All CLI inputs therefore go through `--in=<file>`
# (byte-exact). Never `$string | interop-cli ...`.

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $env:TEMP "pocketpgp-interop"

# Kill any gpg-agent still holding sockets in the scratch home BEFORE
# wiping it - stale agents cause sporadic "socket file removed - retrying"
# failures in later runs.
$env:GNUPGHOME = "$work\gnupg"
gpgconf --kill gpg-agent 2>$null | Out-Null

if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path "$work\store", "$work\gnupg", "$work\artifacts" | Out-Null

$env:POCKETPGP_DATA_DIR = "$work\store"
$cli = Join-Path $root "src-tauri\target\debug\interop-cli.exe"

$script:pass = 0
$script:fail = 0

function Case($name, [scriptblock]$body) {
    try {
        & $body
        Write-Host "PASS  $name" -ForegroundColor Green
        $script:pass++
    } catch {
        Write-Host "FAIL  $name -- $($_.Exception.Message)" -ForegroundColor Red
        $script:fail++
    }
}

function Assert($cond, $msg) {
    if (-not $cond) { throw $msg }
}

function Invoke-Gpg([string[]]$argv) {
    & gpg @argv 2>&1
}

function CliOut([string]$path, [string[]]$argv) {
    # Byte-exact: the CLI writes the file itself via --out=<path>.
    # (PowerShell pipes would rewrite line endings and break armor.)
    & $cli @argv "--out=$path" | Out-Null
    Assert ($LASTEXITCODE -eq 0) "interop-cli $($argv -join ' ') failed"
}

function CliErr([string]$path, [string[]]$argv) {
    & $cli @argv 2> $path
    Assert ($LASTEXITCODE -ne 0) "interop-cli $($argv -join ' ') unexpectedly succeeded"
}

function WriteAscii([string]$path, [string]$text) {
    # ASCII-only content encodes identically as BOM-less UTF-8.
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

# --------------------------------------------------------------------------
Write-Host "== building interop-cli ==" -ForegroundColor Cyan
Push-Location "$root\src-tauri"
cargo build --bin interop-cli 2>&1 | Select-Object -Last 2 | Write-Host
Pop-Location
if (-not (Test-Path $cli)) { Write-Host "interop-cli build failed" -ForegroundColor Red; exit 1 }

# ==========================================================================
# App -> GnuPG
# ==========================================================================

Case "A1: v4 ECC key imports into GnuPG (expiry visible)" {
    $fpr = (& $cli generate "Alice Interop" "alice-interop@example.com" ecc compatible "interop-pass-1" 365 | Select-Object -Last 1).Trim()
    Assert ($fpr -match "^[0-9A-F]{40}$") "bad fpr: $fpr"

    CliOut "$work\artifacts\alice.pub.asc" @("export-public", $fpr)
    Invoke-Gpg @("--import", "$work\artifacts\alice.pub.asc") | Out-Null
    Assert ($LASTEXITCODE -eq 0) "gpg import failed"

    $list = (Invoke-Gpg @("--list-keys") -join "`n")
    Assert ($list -match "alice-interop@example.com") "key not listed"

    # Expiry must be recorded and in the future.
    # pub:<type>:<validity>:<bits>:<algo>:<keyid>:<created>:<expires>:...
    $colon = (Invoke-Gpg @("--list-keys", "--with-colons") -join "`n")
    $publine = ($colon -split "`n" | Select-String "^pub:" | Select-Object -First 1).ToString()
    $expires = [int64](($publine -split ":")[6])
    Assert ($expires -gt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) "no future expiry recorded by gpg"
}

Case "A2: v4 RSA-4096 key imports into GnuPG" {
    $fpr = (& $cli generate "Bob Rsa" "bob-rsa@example.com" rsa4096 compatible "interop-pass-2" 0 | Select-Object -Last 1).Trim()
    CliOut "$work\artifacts\bob.pub.asc" @("export-public", $fpr)
    Invoke-Gpg @("--import", "$work\artifacts\bob.pub.asc") | Out-Null
    Assert ($LASTEXITCODE -eq 0) "gpg import failed"
    $list = (Invoke-Gpg @("--list-keys") -join "`n")
    Assert ($list -match "bob-rsa@example.com") "key not listed"
}

Case "A3: sign+encrypt text round-trips through GnuPG" {
    $fpr = (& $cli generate "Carol Sig" "carol-sig@example.com" ecc compatible "interop-pass-3" 0 | Select-Object -Last 1).Trim()
    WriteAscii "$work\artifacts\msg.txt" "The quick brown fox jumps over the lazy dog.`n"

    # Import the SECRET into gpg so it can decrypt and check our signature.
    CliOut "$work\artifacts\carol.sec.asc" @("export-secret", $fpr)
    Invoke-Gpg @("--batch", "--import", "$work\artifacts\carol.sec.asc") | Out-Null
    Assert ($LASTEXITCODE -eq 0) "gpg secret import failed"

    CliOut "$work\artifacts\msg.asc" @("encrypt", "compatible", $fpr, "+sign:$($fpr):interop-pass-3", "--in=$work\artifacts\msg.txt")

    $dec = (Invoke-Gpg @("--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "interop-pass-3", "-d", "$work\artifacts\msg.asc") -join "`n")
    Assert ($LASTEXITCODE -eq 0) "gpg decrypt failed"
    Assert ($dec -match "quick brown fox") "plaintext mismatch"
    Assert ($dec -match "Good signature from") "gpg did not verify the embedded signature"
}

Case "A4: clearsigned text verifies in GnuPG" {
    $fpr = (& $cli generate "Dave Clear" "dave-clear@example.com" ecc compatible "interop-pass-4" 0 | Select-Object -Last 1).Trim()
    CliOut "$work\artifacts\dave.pub.asc" @("export-public", $fpr)
    Invoke-Gpg @("--import", "$work\artifacts\dave.pub.asc") | Out-Null

    WriteAscii "$work\artifacts\dave-input.txt" "clearsigned hello`nline two`n"
    CliOut "$work\artifacts\dave.clear.asc" @("sign-cleartext", $fpr, "interop-pass-4", "--in=$work\artifacts\dave-input.txt")

    $v = (Invoke-Gpg @("--verify", "$work\artifacts\dave.clear.asc") -join "`n")
    Assert ($LASTEXITCODE -eq 0) "gpg verify failed"
    Assert ($v -match "Good signature from") "no good-signature line"
}

Case "A5: passphrase-protected secret key file imports into GnuPG" {
    # (The import itself ran in A3.) Here: the armored secret must be an
    # encrypted-at-rest PRIVATE KEY BLOCK, and gpg must list the full key
    # INCLUDING its encryption subkey (ssb, not ssb# = secret present).
    $sec = Get-Content "$work\artifacts\carol.sec.asc" -Raw
    Assert ($sec -match "BEGIN PGP PRIVATE KEY BLOCK") "not a private key block"
    $list = (Invoke-Gpg @("--list-secret-keys") -join "`n")
    Assert ($list -match "carol-sig@example.com") "secret not in gpg ring"
    Assert ($list -match "ssb") "secret subkey not in gpg ring"
    Assert ($list -notmatch "ssb#") "gpg marks our secret subkey as unusable (ssb#)"
}

# ==========================================================================
# GnuPG -> App
# ==========================================================================

Case "B1: gpg --export-secret-keys -a imports into the app" {
    $batch = "%no-protection`nKey-Type: RSA`nKey-Length: 3072`nKey-Usage: sign cert`nSubkey-Type: RSA`nSubkey-Length: 3072`nSubkey-Usage: encrypt`nName-Real: Eve Gpg`nName-Email: eve-gpg@example.com`nExpire-Date: 0`n%commit"
    WriteAscii "$work\artifacts\eve.batch" $batch
    Invoke-Gpg @("--batch", "--generate-key", "$work\artifacts\eve.batch") | Out-Null
    Assert ($LASTEXITCODE -eq 0) "gpg keygen failed"

    Invoke-Gpg @("--batch", "--yes", "--export-secret-keys", "-a", "eve-gpg@example.com") | Set-Content -Encoding ascii "$work\artifacts\eve.sec.asc"
    Assert ($LASTEXITCODE -eq 0) "gpg export-secret failed"

    & $cli import "--in=$work\artifacts\eve.sec.asc" | Out-Null
    Assert ($LASTEXITCODE -eq 0) "app import failed"

    $list = (& $cli list) -join "`n"
    Assert ($list -match "secret=True.*eve-gpg@example.com") "imported key lacks secret"
}

Case "B2: message encrypted by GnuPG decrypts in the app" {
    $fpr = (& $cli generate "Frank Enc" "frank-enc@example.com" ecc compatible "interop-pass-6" 0 | Select-Object -Last 1).Trim()
    CliOut "$work\artifacts\frank.pub.asc" @("export-public", $fpr)
    Invoke-Gpg @("--import", "$work\artifacts\frank.pub.asc") | Out-Null

    WriteAscii "$work\artifacts\gpgmsg.txt" "secret message from gpg 42`n"
    Invoke-Gpg @("--batch", "--yes", "--trust-model", "always", "-a", "-e", "-r", "frank-enc@example.com", "$work\artifacts\gpgmsg.txt") | Out-Null
    Assert ($LASTEXITCODE -eq 0) "gpg encrypt failed"

    $out = (& $cli decrypt "interop-pass-6" "--in=$work\artifacts\gpgmsg.txt.asc") -join "`n"
    Assert ($LASTEXITCODE -eq 0) "app decrypt failed"
    Assert ($out -match "secret message from gpg 42") "plaintext mismatch"
}

Case "B3: message signed by an old RSA key verifies in the app" {
    $batch = "%no-protection`nKey-Type: RSA`nKey-Length: 2048`nKey-Usage: sign`nName-Real: Grace Old`nName-Email: grace-old@example.com`nExpire-Date: 0`n%commit"
    WriteAscii "$work\artifacts\grace.batch" $batch
    Invoke-Gpg @("--batch", "--generate-key", "$work\artifacts\grace.batch") | Out-Null
    Assert ($LASTEXITCODE -eq 0) "gpg RSA keygen failed"

    Invoke-Gpg @("--batch", "--yes", "--local-user", "grace-old@example.com", "--clearsign", "$work\artifacts\msg.txt") | Out-Null
    Assert ($LASTEXITCODE -eq 0) "gpg clearsign failed"

    Invoke-Gpg @("--batch", "--export", "-a", "grace-old@example.com") | Set-Content -Encoding ascii "$work\artifacts\grace.pub.asc"
    & $cli import "--in=$work\artifacts\grace.pub.asc" | Out-Null
    Assert ($LASTEXITCODE -eq 0) "app import failed"

    $out = (& $cli verify "--in=$work\artifacts\msg.txt.asc" 2>&1) -join "`n"
    Assert ($LASTEXITCODE -eq 0) "app verify failed"
    Assert ($out -match "SIG: .* valid=true") "signature not valid"
    Assert ($out -match "source=imported") "signer not attributed to imported key"
}

Case "B4: key with bumped subkey expiry parses in the app" {
    $batch = "%no-protection`nKey-Type: RSA`nKey-Length: 3072`nKey-Usage: sign cert`nSubkey-Type: RSA`nSubkey-Length: 3072`nSubkey-Usage: encrypt`nName-Real: Henry Bump`nName-Email: henry-bump@example.com`nExpire-Date: 0`n%commit"
    WriteAscii "$work\artifacts\henry.batch" $batch
    Invoke-Gpg @("--batch", "--generate-key", "$work\artifacts\henry.batch") | Out-Null

    # Bump the SUBKEY expiry to 14 weeks. --quick-set-expire demands the
    # full fingerprints (colon fpr: lines), not short key ids.
    $colon = (Invoke-Gpg @("--list-keys", "--with-colons", "henry-bump@example.com") -join "`n")
    $fprlines = ($colon -split "`n" | Select-String "^fpr:")
    $primaryfpr = ($fprlines[0].ToString() -split ":")[9]
    $subkeyfpr = ($fprlines[1].ToString() -split ":")[9]
    Assert ($primaryfpr -match "^[0-9A-F]{40}$") "could not read primary fingerprint"
    Assert ($subkeyfpr -match "^[0-9A-F]{40}$") "could not read subkey fingerprint"
    Invoke-Gpg @("--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-set-expire", $primaryfpr, "14w", $subkeyfpr) | Out-Null
    Assert ($LASTEXITCODE -eq 0) "gpg set-expire failed"

    Invoke-Gpg @("--batch", "--export", "-a", "henry-bump@example.com") | Set-Content -Encoding ascii "$work\artifacts\henry.pub.asc"
    & $cli import "--in=$work\artifacts\henry.pub.asc" | Out-Null
    Assert ($LASTEXITCODE -eq 0) "app import failed"

    $list = (& $cli list) -join "`n"
    Assert ($list -match "henry-bump@example.com") "key not listed after expiry bump"
}

# ==========================================================================
# Negative cases
# ==========================================================================

Case "N1: RFC 9580 profile to a v4 recipient fails cleanly" {
    $fpr = (& $cli generate "Ivy Neg" "ivy-neg@example.com" ecc compatible "pw" 0 | Select-Object -Last 1).Trim()
    WriteAscii "$work\artifacts\n1.txt" "negative test`n"
    CliErr "$work\artifacts\n1.err" @("encrypt", "rfc9580", $fpr, "--in=$work\artifacts\n1.txt")
    $err = Get-Content "$work\artifacts\n1.err" -Raw
    Assert ($err -match "RFC 9580") "error does not explain the profile rule"
}

Case "N2: garbled paste is rejected cleanly" {
    WriteAscii "$work\artifacts\n2.txt" "-----BEGIN PGP MESSAGE-----`n!!! not base64 at all !!!`n-----END PGP MESSAGE-----`n"
    CliErr "$work\artifacts\n2.err" @("decrypt", "pw", "--in=$work\artifacts\n2.txt")
    $err = Get-Content "$work\artifacts\n2.err" -Raw
    Assert ($err -match "ERROR") "no clean error message"
}

Case "N3: oversized paste is rejected" {
    WriteAscii "$work\artifacts\n3.txt" (("A" * (1024 * 1024 + 10)) + "`n-----END PGP MESSAGE-----`n")
    CliErr "$work\artifacts\n3.err" @("decrypt", "pw", "--in=$work\artifacts\n3.txt")
    $err = Get-Content "$work\artifacts\n3.err" -Raw
    Assert ($err -match "1 MB") "error does not mention the size limit"
}

Case "N4: revoked key is blocked from encrypt" {
    $fpr = (& $cli generate "Jack Rev" "jack-rev@example.com" ecc compatible "pw" 0 | Select-Object -Last 1).Trim()

    # Make the key revoked in the store: merge our revocation cert via gpg
    # (which folds the revocation signature into the public key), re-import.
    CliOut "$work\artifacts\jack.rev.asc" @("export-revocation", $fpr)
    CliOut "$work\artifacts\jack.pub.asc" @("export-public", $fpr)
    Invoke-Gpg @("--import", "$work\artifacts\jack.pub.asc") | Out-Null
    Invoke-Gpg @("--import", "$work\artifacts\jack.rev.asc") | Out-Null
    Assert ($LASTEXITCODE -eq 0) "gpg revocation import failed"

    Invoke-Gpg @("--batch", "--export", "-a", "jack-rev@example.com") | Set-Content -Encoding ascii "$work\artifacts\jack.revoked.pub.asc"
    & $cli import "--in=$work\artifacts\jack.revoked.pub.asc" | Out-Null
    Assert ($LASTEXITCODE -eq 0) "app import of revoked key failed"

    $list = (& $cli list) -join "`n"
    Assert ($list -match "revoked=True") "key not marked revoked"

    WriteAscii "$work\artifacts\n4.txt" "to a revoked key`n"
    CliErr "$work\artifacts\n4.err" @("encrypt", "compatible", $fpr, "--in=$work\artifacts\n4.txt")
    $err = Get-Content "$work\artifacts\n4.err" -Raw
    Assert ($err -match "revoked") "error does not mention revocation"
}

# ==========================================================================
# Whitespace torture (acceptance criterion 3)
# ==========================================================================

Case "W1: whitespace-mangled armor still decrypts" {
    $fpr = (& $cli generate "Kate Mangle" "kate-mangle@example.com" ecc compatible "pw" 0 | Select-Object -Last 1).Trim()
    WriteAscii "$work\artifacts\kate-input.txt" "mangle me 42`n"
    CliOut "$work\artifacts\kate.msg.asc" @("encrypt", "compatible", $fpr, "--in=$work\artifacts\kate-input.txt")

    # Mangle exactly like a chat app would: body joined to one long line,
    # re-wrapped at an odd width, stray blank lines and trailing spaces.
    # (Explicit array building - PowerShell's operator precedence around
    # `+ ... -join` silently produces garbage otherwise.)
    $raw = [System.IO.File]::ReadAllText("$work\artifacts\kate.msg.asc").TrimEnd("`n")
    $lines = $raw -split "`n"
    $head = $lines[0]
    $tail = $lines[-1]
    $body = ($lines[1..($lines.Count - 2)] -join "")
    $wrapped = [regex]::Split($body, "(.{37})") | Where-Object { $_ }

    $parts = @($head, "")
    foreach ($w in $wrapped) { $parts += ($w + "   ") }
    $parts += ""
    $parts += $tail
    $mangled = ($parts -join "`n") + "`n"
    WriteAscii "$work\artifacts\kate.mangled.asc" $mangled

    $out = (& $cli decrypt "pw" "--in=$work\artifacts\kate.mangled.asc") -join "`n"
    Assert ($LASTEXITCODE -eq 0) "mangled armor failed to parse"
    Assert ($out -match "mangle me 42") "plaintext mismatch after mangling"
}

# --------------------------------------------------------------------------
Write-Host ""
Write-Host "==================== interop matrix summary ===================="
Write-Host ("PASS: {0}   FAIL: {1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 } else { Write-Host "ALL GREEN" -ForegroundColor Green; exit 0 }
