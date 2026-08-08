# zodiac-crypto

Authenticated encryption (AES-256-GCM) whose key is derived from two secrets:

- a **32-symbol recovery key**, randomly generated at encryption time out of a
  fixed table of 50 symbols
- a **passphrase** you choose

The symbols are never chosen manually. Every `Encrypt` call draws a fresh
random permutation of 32 distinct symbols with `crypto/rand`, giving
P(50,32) = 50!/18! ≈ 4.9×10^47 possible sequences. **Order matters** — the key
is a permutation, not a set.

> ### ⚠️ The recovery symbols are shown only once
>
> They are **not** stored in the ciphertext and cannot be recovered from it.
> Write them down, in order, the moment `Encrypt` returns. Losing them (or the
> passphrase) means the data is permanently unrecoverable.

## The 50 symbols

<p align="center">
  <img src="docs/symbol-grid.svg" alt="The 50 zodiac-crypto symbols, drawn as vector artwork" width="100%">
</p>

The table is fixed and order-sensitive: index 0 is `U+25CB`, index 49 is
`U+2660`. The artwork above is drawn as vector geometry
(`docs/gen_symbols.py` → `docs/symbol-grid.svg`), so it renders identically
everywhere regardless of which fonts are installed.

## Design

| Stage | Choice |
| --- | --- |
| Key derivation | Argon2id, `time=3`, `memory=64 MiB`, `threads=4`, 32-byte master key, 16-byte random salt per message |
| Key separation | HKDF-SHA256 → `encKey` (32 B, info `zodiac-crypto-v1-enc`) and `macKey` (16 B, info `zodiac-crypto-v1-checksum`) |
| Fast wrong-key check | 8-byte truncated `HMAC-SHA256(macKey, salt‖nonce)`, compared with `crypto/subtle.ConstantTimeCompare` before GCM is touched |
| Encryption | AES-256-GCM, 12-byte random nonce, AAD = `zc1` so the version prefix is authenticated |
| Encoding | `zc1:` + base64url (no padding) of `salt(16) ‖ nonce(12) ‖ checksum(8) ‖ ciphertext+tag` |

Additional hardening: only `crypto/rand` is used, no code path panics, key
material and the Argon2id input are zeroed after use, plaintext is capped at
10 MB, and `Decrypt` adds a constant 150 ms delay on every path (success or
failure alike) to slow down online brute forcing.

## Library

```go
package main

import (
	"fmt"
	"log"

	zodiaccrypto "github.com/vhamed02/zodiac-crypto"
)

func main() {
	ciphertext, symbols, err := zodiaccrypto.Encrypt("attack at dawn", "correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("ciphertext:", ciphertext)
	fmt.Println("recovery symbols:", zodiaccrypto.FormatSymbols(symbols))

	plaintext, err := zodiaccrypto.Decrypt(ciphertext, symbols, "correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("plaintext:", plaintext)
}
```

### API

| Function | Behaviour |
| --- | --- |
| `Encrypt(plaintext, passphrase string) (string, []string, error)` | Encrypts and returns the `zc1:…` payload plus the 32 freshly generated symbols. |
| `Decrypt(ciphertext string, symbols []string, passphrase string) (string, error)` | Recovers the plaintext from the payload, the symbols in order, and the passphrase. |
| `FormatSymbols(symbols []string) string` | Joins the symbols with single spaces for display and copying. |
| `ParseSymbols(s string) ([]string, error)` | Parses a pasted symbol key, tolerating any run of Unicode whitespace, and NFC-normalizes each symbol. |
| `SymbolTable() []string` | Returns a copy of the 50-symbol table. |

Every symbol input is NFC-normalized before it is mapped to an index, so
encoding variance from a terminal or clipboard never causes a spurious
wrong-key failure. Pasted keys with double spaces, tabs, newlines, or
surrounding whitespace parse identically to a clean single-space form.

### Errors

All errors satisfy `errors.Is` against these sentinels:

| Sentinel | Meaning |
| --- | --- |
| `ErrInvalidSymbols` | Not exactly 32 distinct symbols from the table. |
| `ErrAuthFailed` | Wrong symbols, wrong passphrase, or tampered data. |
| `ErrCorruptData` | Missing `zc1:` prefix, invalid base64url, or a truncated payload. |
| `ErrInputTooLarge` | Plaintext above the 10 MB cap (rejected before any crypto work). |

## CLI

```
go build -o zodiaccrypto ./cmd/zodiaccrypto
```

```
zodiaccrypto encrypt [--passphrase-stdin]
zodiaccrypto decrypt [--input <ciphertext>] [--symbols <key>] [--passphrase-stdin]
```

### Encrypt

```
$ echo "attack at dawn" | ./zodiaccrypto encrypt
Passphrase:
Ciphertext:
zc1:0mUS3vP6dQ...

Recovery symbols (32):
★ ◐ ⌘ ○ ♠ ⊗ ✧ ◉ …

WARNING: the recovery symbols above are shown only once and are not stored
anywhere. Save them now, in order, in a safe place. Without them the data is
permanently unrecoverable.
```

The plaintext is read from stdin verbatim, including a trailing newline if the
input has one. The passphrase is prompted on the terminal and never echoed
(`golang.org/x/term`).

### Decrypt

```
$ ./zodiaccrypto decrypt --input 'zc1:0mUS3vP6dQ...'
Symbol key (32 symbols, space separated): ★ ◐ ⌘ ○ ♠ ⊗ ✧ ◉ …
Passphrase:
attack at dawn
```

Without `--input`, the ciphertext is read from the first line of stdin, so
piping the payload still leaves the symbol key and passphrase to be entered on
the terminal:

```
$ printf 'zc1:0mUS3vP6dQ...\n' | ./zodiaccrypto decrypt
Symbol key (32 symbols, space separated): ★ ◐ ⌘ ○ ♠ ⊗ ✧ ◉ …
Passphrase:
attack at dawn
```

The symbol key may be pasted with any whitespace irregularities. Pass
`--symbols` and `--passphrase-stdin` to skip the prompts entirely. Failures
print a single user-facing message (`ErrAuthFailed`, `ErrInvalidSymbols`, or
`ErrCorruptData`) and exit with a non-zero status.

### Non-interactive use

Prompts are read from the terminal (`/dev/tty`) even when stdin is a pipe.
When no terminal is available, they fall back to stdin in this order:

- `encrypt`: passphrase (only with `--passphrase-stdin`), then the plaintext
- `decrypt`: ciphertext (unless `--input`), symbol key, passphrase

```
printf 'my-passphrase\nattack at dawn' | ./zodiaccrypto encrypt --passphrase-stdin
./zodiaccrypto decrypt --input 'zc1:…' --symbols '★ ◐ ⌘ …' --passphrase-stdin <<< 'my-passphrase'
```

## Development

```
go build ./...
go vet ./...
gofmt -l .
go test ./... -race
```

The test suite covers round-trips (including empty, Unicode, and 10 MB inputs),
every wrong-key and tampering path, AAD binding, whitespace-tolerant parsing,
symbol-table integrity, concurrency under `-race`, a frozen ciphertext
regression vector, and the CLI end to end.
