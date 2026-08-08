# Implementation Prompt — Zodiac Symbol Key Encryption System (Go)

## Project Overview

Build a Go **library** plus a thin **CLI** on top of it, implementing
authenticated encryption (AES-256-GCM) whose key is derived from the
combination of:

- a **32-symbol distinct sequence**, drawn from a fixed table of 50 symbols
- a text **passphrase**

via Argon2id and HKDF. The 32 symbols are **generated randomly and securely
at encryption time** (never chosen manually by the user) and returned as
part of the output — they act as a recovery key, similar in spirit to a
crypto wallet seed phrase.

This must be production-grade: no panics, no bugs, full test coverage,
standard idiomatic Go project layout.

---

## Fixed Table of 50 Symbols (index 0–49)

This exact table must be used in the code (order matters — do not change it):

```
 0 ○   1 ●   2 △   3 ▲   4 ▽   5 ▼   6 □   7 ■   8 Ω   9 ↯
10 ☆  11 ★  12 ✦  13 ✧  14 ✩  15 ✪  16 ∅  17 ∈  18 ♃  19 Σ
20 ✯  21 ⊕  22 ⊗  23 ⊙  24 ⊖  25 ⊘  26 ⊚  27 ⊛  28 ⊝  29 ⊞
30 ⊟  31 ⊠  32 ⊡  33 ⌖  34 ⌁  35 ⌂  36 ⌘  37 ⌗  38 ◈  39 ◉
40 ◌  41 ◍  42 ◐  43 ◑  44 ◒  45 ◓  46 ♢  47 ♧  48 ♤  49 ♠
```

Exact Unicode codepoints (define these as `rune`/`\uXXXX` literals in Go
source, not by pasting raw characters, to avoid copy-paste corruption):

```
U+25CB U+25CF U+25B3 U+25B2 U+25BD U+25BC U+25A1 U+25A0 U+03A9 U+21AF
U+2606 U+2605 U+2726 U+2727 U+2729 U+272A U+2205 U+2208 U+2643 U+03A3
U+272F U+2295 U+2297 U+2299 U+2296 U+2298 U+229A U+229B U+229D U+229E
U+229F U+22A0 U+22A1 U+2316 U+2301 U+2302 U+2318 U+2317 U+25C8 U+25C9
U+25CC U+25CD U+25D0 U+25D1 U+25D2 U+25D3 U+2662 U+2667 U+2664 U+2660
```

All 50 symbols are single-codepoint and already NFC-normalized. Verify this
with a dedicated unit test rather than assuming it.

---

## Architecture

### 1. Symbol key (auto-generated, never manual)

- On every `Encrypt` call, use `crypto/rand` with a **Fisher-Yates shuffle**
  to draw a random permutation of 32 **distinct** symbols out of the 50-symbol
  table above.
- Key space: P(50,32) = 50!/18! ≈ 4.9×10^47 possible sequences.
- These 32 symbols, in the exact order generated, are returned as the second
  output value of `Encrypt`. They are the recovery key — they are **not**
  stored inside the ciphertext.
- **Order matters**: this is a permutation, not a set. Swapping two symbols
  produces a completely different derived key.

### 2. Unicode normalization (NFC)

- Every symbol input (whether coming from user input during `Decrypt`/CLI, or
  internally) must be Unicode-normalized to NFC form via
  `golang.org/x/text/unicode/norm` **before** being mapped to an index, so
  that Unicode encoding variance never causes a spurious "wrong key" failure.

### 3. Key derivation — Argon2id

- Input: `bytes(32 symbol indices) || passphrase (UTF-8 bytes)`
- Library: `golang.org/x/crypto/argon2`, function `argon2.IDKey`
- Parameters (per OWASP 2026 recommendation for new applications):
  - `time = 3`
  - `memory = 64 * 1024` (64 MiB, expressed in KiB)
  - `threads = 4`
  - `keyLen = 32` (256-bit output — this is the master key)
- Salt: 16 random bytes from `crypto/rand`, freshly generated on every
  `Encrypt` call.

### 4. HKDF — key separation

- From the Argon2id master key, use `golang.org/x/crypto/hkdf` (SHA-256
  based) to derive **two separate subkeys**, each with a distinct `info`
  context string:
  - `encKey` (32 bytes) — info = `"zodiac-crypto-v1-enc"`
  - `macKey` (16 bytes) — info = `"zodiac-crypto-v1-checksum"`
- This follows standard cryptographic best practice: a single raw key must
  never serve two different purposes simultaneously.

### 5. Fast checksum (early wrong-key detection)

- Before attempting AES-GCM decryption, store a short checksum (8 bytes,
  derived from `HMAC-SHA256(macKey, salt || nonce)`, truncated) inside the
  payload.
- On `Decrypt`, recompute this checksum using the newly derived key and
  compare it. On mismatch, return `ErrAuthFailed` immediately — without
  attempting `GCM.Open`. This gives a clearer error path and avoids
  unnecessary computation.
- **The checksum comparison must use `crypto/subtle.ConstantTimeCompare`**,
  never `==` or plain `bytes.Equal`, to avoid timing side-channels.

### 6. Encryption — AES-256-GCM

- Library: `crypto/aes` + `crypto/cipher` (standard library GCM — do not
  hand-roll it).
- Nonce: 12 random bytes from `crypto/rand`, freshly generated on every
  `Encrypt` call.
- **AAD (Additional Authenticated Data)**: pass the version prefix string
  `"zc1"` (without the colon) as AAD to `cipher.Seal`. This ensures that if
  the version prefix in a payload is later tampered with, GCM authentication
  fails immediately (because the AAD no longer matches), rather than the
  prefix being just an unauthenticated text label.

### 7. Output payload structure

```
version_prefix ":" base64url_no_padding( salt(16) || nonce(12) || checksum(8) || ciphertext+GCMtag )
```

Example shape: `zc1:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx...`

- Base64: `base64.RawURLEncoding` (URL-safe, no padding) from the standard
  `encoding/base64` package.
- This whole string is the final output, safe to copy/store/transmit.

### 8. Displaying the symbol key to the user

- Whenever the 32 symbols are shown to a human (function output, CLI print,
  etc.), they must be **space-separated**, e.g.:
  `★ ◐ ⌘ ○ ♠ ...`
  to avoid visual ambiguity between adjacent similar-looking symbols.
- This separator is purely a display/copy convenience. The Go function
  itself must return `symbols` as `[]string` (one symbol per element), not a
  pre-joined string. Provide a separate `FormatSymbols([]string) string`
  helper for the space-joined display form, so callers have access to both
  the structured form and the display form.

### 9. Whitespace-tolerant parsing (critical for copy-paste round-trips)

- When the user copies the space-separated symbol key and pastes it back in
  during decryption (library call or CLI), parsing **must tolerate
  whitespace irregularities** introduced by copy-paste, terminals, or
  clipboard managers:
  - Multiple consecutive spaces between symbols
  - Leading/trailing whitespace (spaces, tabs, newlines)
  - Tabs or other Unicode whitespace used as separators instead of a plain
    space
- `ParseSymbols` must split on **any run of Unicode whitespace**
  (`unicode.IsSpace`, e.g. via `strings.FieldsFunc` or `strings.Fields`),
  discard empty fields, and NFC-normalize each resulting token before
  validation. A pasted key with extra/irregular spacing must parse
  identically to a cleanly single-space-separated one — it must **never**
  cause a spurious `ErrInvalidSymbols` due to whitespace alone.
- Add a dedicated unit test pasting the same 32 symbols with double spaces,
  tabs, and leading/trailing whitespace, confirming identical parse results
  and a successful decrypt.

### 10. Public library API

```go
package zodiaccrypto

// Encrypt encrypts plaintext and returns the newly generated ciphertext
// along with the randomly generated 32-symbol recovery key.
// symbols always has exactly 32 elements, each one of the 50 fixed-table
// symbols, with no repeats.
func Encrypt(plaintext string, passphrase string) (ciphertext string, symbols []string, err error)

// Decrypt takes the ciphertext string, the 32 symbols (in order), and the
// passphrase, and returns the original plaintext.
func Decrypt(ciphertext string, symbols []string, passphrase string) (plaintext string, err error)

// FormatSymbols joins symbols with a single space for display/copying.
func FormatSymbols(symbols []string) string

// ParseSymbols parses a symbol key pasted/typed by a user into []string.
// It must tolerate multiple spaces, tabs, and leading/trailing whitespace
// (see section 9), and NFC-normalize each symbol.
func ParseSymbols(s string) ([]string, error)
```

### 11. Sentinel errors

```go
var (
    ErrInvalidSymbols = errors.New("invalid symbol sequence: must be exactly 32 distinct symbols from the valid table")
    ErrAuthFailed     = errors.New("authentication failed: wrong symbols, passphrase, or tampered data")
    ErrCorruptData    = errors.New("corrupt or malformed ciphertext")
    ErrInputTooLarge  = errors.New("plaintext exceeds maximum allowed size (10MB)")
)
```

All returned errors must support `errors.Is` — return these sentinels
directly or wrap them with `fmt.Errorf("...: %w", ErrX)`.

### 12. Production hardening

- Use **only** `crypto/rand` for every random operation (symbol shuffle,
  salt, nonce). Using `math/rand` anywhere in the crypto path is forbidden.
- No `panic` in any normal execution path. Every failure mode (invalid
  input, corrupt base64, wrong length, etc.) must return an `error`.
- After use, zero out (`defer`) the passphrase bytes and all derived key
  material (master key, encKey, macKey) so they don't linger in memory.
- Plaintext input size cap: **10 MB** (10 * 1024 * 1024 bytes). If exceeded,
  return `ErrInputTooLarge` immediately, before any cryptographic work.
- On the `Decrypt` path, add a constant artificial delay of 100–200ms (e.g.
  `time.Sleep`) to slow down online brute-force attempts if this function is
  ever exposed behind a network service. This delay must be applied
  identically whether the operation succeeds or fails, so it doesn't itself
  become a timing side-channel.

### 13. Decrypt-time validation order (before any crypto work)

1. Parse/normalize the symbol input (see section 9).
2. `len(symbols)` must be exactly 32.
3. Every symbol (post-NFC) must belong to the 50-symbol table.
4. No symbol may repeat.
5. `ciphertext` must start with prefix `"zc1:"`.
6. The remainder must be valid `base64.RawURLEncoding`.
7. Decoded length must be at least `16+12+8` bytes (salt+nonce+checksum),
   otherwise `ErrCorruptData`.

Any failure here must return the appropriate error (`ErrInvalidSymbols` or
`ErrCorruptData`) immediately — never proceed to Argon2id/GCM on clearly
invalid input, since Argon2id is deliberately slow.

---

## CLI

Build a thin CLI on top of the library, in `cmd/zodiaccrypto/main.go`, using
the standard library `flag` package (no need for external CLI frameworks
unless you judge one clearly improves UX — keep dependencies minimal).

### Commands

```
zodiaccrypto encrypt [--passphrase-stdin]
zodiaccrypto decrypt [--passphrase-stdin]
```

**`encrypt`**:
- Reads plaintext from stdin (supports piping: `echo "secret" | zodiaccrypto encrypt`).
- Prompts interactively for the passphrase if not piped (do not echo it to
  the terminal — use `golang.org/x/term.ReadPassword` on the passphrase
  prompt).
- Prints to stdout:
  - The ciphertext string (`zc1:...`) on its own line.
  - The 32-symbol recovery key, space-separated via `FormatSymbols`, on its
    own line, clearly labeled.
  - A prominent warning that the symbol key is shown only once and must be
    saved immediately, since losing it makes the data permanently
    unrecoverable.

**`decrypt`**:
- Reads the ciphertext string from stdin or a `--input` flag.
- Prompts for the 32-symbol key (accepts pasted input with any whitespace
  irregularities — see section 9) and the passphrase (masked, via
  `golang.org/x/term.ReadPassword`).
- Prints the decrypted plaintext to stdout on success.
- On failure, prints a clear, user-facing error message distinguishing
  wrong-key/passphrase (`ErrAuthFailed`) from malformed input
  (`ErrInvalidSymbols`, `ErrCorruptData`) — do not leak internal details
  beyond the sentinel error's message.
- Exits with a non-zero status code on any error.

### CLI-specific tests

- Golden/integration test: run `encrypt` then feed its exact output into
  `decrypt` (in-process, calling the CLI's command functions directly rather
  than shelling out) and confirm the original plaintext is recovered.
- Test that pasting the symbol key with irregular whitespace (double spaces,
  tabs, trailing newline) during `decrypt` still succeeds.

---

## Required Unit Tests (`_test.go`)

1. **Successful round-trip**: Encrypt a string → Decrypt with the same
   symbols/passphrase → must return the exact original plaintext.
2. **Round-trip edge cases**: empty string, Unicode/multi-byte text, a very
   large string near the 10MB cap.
3. **Wrong symbol**: alter one of the 32 symbols → expect `ErrAuthFailed`
   (or `ErrInvalidSymbols` if the substituted symbol isn't in the table).
4. **Wrong symbol order**: same 32 symbols, shuffled → expect `ErrAuthFailed`.
5. **Wrong passphrase** → expect `ErrAuthFailed`.
6. **Wrong symbol count**: fewer or more than 32 → expect `ErrInvalidSymbols`.
7. **Duplicate symbol in Decrypt input** → expect `ErrInvalidSymbols`.
8. **Symbol outside the 50-symbol table** → expect `ErrInvalidSymbols`.
9. **Tampered ciphertext**: flip a byte in the middle of the base64 payload
   → expect `ErrAuthFailed` or `ErrCorruptData` depending on which part of
   the payload was corrupted.
10. **Tampered version prefix**: change `"zc1:"` to something else → expect
    an error (malformed format); also add a lower-level test (via an
    internal, non-exported helper) that directly confirms GCM open fails on
    AAD mismatch.
11. **Invalid base64**: inject illegal characters into the payload → expect
    `ErrCorruptData`.
12. **Oversized input**: plaintext > 10MB → expect `ErrInputTooLarge`,
    without Argon2id ever running (a timing-based or instrumented check is
    optional but encouraged).
13. **Symbol table integrity**: a dedicated test asserting the table has
    exactly 50 entries, all unique, and all already NFC-normalized.
14. **Fixed test vector (regression test)**: using an internal, non-exported
    function that accepts an injected salt, nonce, and fixed 32-symbol
    sequence (bypassing the random generation just for this test), assert
    the resulting ciphertext exactly matches a hardcoded precomputed value.
    This guards against future code changes silently altering the
    cryptographic behavior.
15. **FormatSymbols / ParseSymbols round-trip**: symbols → space-joined
    format → parse again → must equal the original `[]string`.
16. **Whitespace-tolerant parsing**: paste the same 32 symbols with double
    spaces, tabs, and leading/trailing whitespace → `ParseSymbols` must
    produce an identical result to the clean single-space form, and the
    resulting decrypt must succeed.
17. **Concurrency**: run `go test -race` across parallel `Encrypt`/`Decrypt`
    calls to confirm no race conditions (since `crypto/rand` and shared
    buffers are involved).
18. **CLI integration tests**: as described in the CLI section above.

---

## Project File Structure

```
zodiaccrypto/
├── go.mod
├── symbols.go              // 50-symbol table, index<->symbol maps, NFC normalize, validation
├── crypto.go                // Argon2id, HKDF, AES-GCM, payload build/parse
├── errors.go                 // sentinel errors
├── zodiaccrypto.go          // public API: Encrypt, Decrypt, FormatSymbols, ParseSymbols
├── zodiaccrypto_test.go     // all tests from the section above (1-17)
├── cmd/
│   └── zodiaccrypto/
│       ├── main.go           // CLI entry point (encrypt/decrypt subcommands)
│       └── main_test.go      // CLI integration tests (item 18)
└── README.md                  // usage examples for both the library and the CLI, plus the one-time-key warning
```

---

## Dependencies (`go.mod`)

```
golang.org/x/crypto/argon2
golang.org/x/crypto/hkdf
golang.org/x/text/unicode/norm
golang.org/x/term
```
(Everything else from the standard library: `crypto/aes`, `crypto/cipher`,
`crypto/rand`, `crypto/hmac`, `crypto/sha256`, `crypto/subtle`,
`encoding/base64`, `errors`, `fmt`, `time`, `strings`, `unicode`, `flag`,
`os`, `bufio`.)

---

## Final Instructions for Claude Code

1. Implement the exact project structure above.
2. Initialize `go.mod` with an appropriate module name and add all
   dependencies.
3. Write each file according to its stated responsibility (respect
   separation of concerns — do not dump everything into one file).
4. Implement all 18 test items above in the appropriate `_test.go` files;
   all must pass.
5. Run `go vet ./...` and `gofmt -l .` and ensure clean output (no
   warnings, no unformatted files).
6. Write a concise `README.md` covering:
   - Library usage example (Encrypt a string, display the symbols, then
     Decrypt).
   - CLI usage example (`encrypt` piping stdin, `decrypt` reading the
     ciphertext and prompting for the symbol key + passphrase).
   - An explicit, prominent warning that the symbols returned by `Encrypt`
     are shown only once and must be saved immediately in a safe place,
     since losing them means permanent, unrecoverable data loss.
7. At the end, show the output of `go build ./...` and
   `go test ./... -race -v` to confirm everything compiles and all tests
   pass.
