package zodiaccrypto

import (
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const testPassphrase = "correct horse battery staple"

const fixedVectorCiphertext = "zc1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaG5ZS5kD6bc8sMDwGpKpCQoeqy1zEv694WpOU2qk0361_9ZUndzFUCwfx_KKpZZGr_11gZkaWRAM"

func mustEncrypt(t *testing.T, plaintext, passphrase string) (string, []string) {
	t.Helper()
	ciphertext, symbols, err := Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt returned an unexpected error: %v", err)
	}
	if len(symbols) != KeySize {
		t.Fatalf("expected %d symbols, got %d", KeySize, len(symbols))
	}
	return ciphertext, symbols
}

func symbolsFromIndices(indices []byte) []string {
	symbols := make([]string, len(indices))
	for i, index := range indices {
		symbols[i] = defaultTable.symbol(index)
	}
	return symbols
}

func symbolOutsideKey(t *testing.T, symbols []string) string {
	t.Helper()
	used := make(map[string]bool, len(symbols))
	for _, symbol := range symbols {
		used[symbol] = true
	}
	for _, candidate := range SymbolTable() {
		if !used[candidate] {
			return candidate
		}
	}
	t.Fatal("no unused symbol left in the table")
	return ""
}

func TestRoundTrip(t *testing.T) {
	plaintext := "attack at dawn"
	ciphertext, symbols := mustEncrypt(t, plaintext, testPassphrase)

	if !strings.HasPrefix(ciphertext, payloadPrefix) {
		t.Fatalf("ciphertext %q is missing the %q prefix", ciphertext, payloadPrefix)
	}

	got, err := Decrypt(ciphertext, symbols, testPassphrase)
	if err != nil {
		t.Fatalf("Decrypt returned an unexpected error: %v", err)
	}
	if got != plaintext {
		t.Fatalf("expected plaintext %q, got %q", plaintext, got)
	}
}

func TestRoundTripEdgeCases(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"unicode":   "سلام دنیا — 🌍 zażółć gęślą jaźń ✦✧✩",
		"multiline": "line one\nline two\r\nline three\t\n",
		"large":     strings.Repeat("z", MaxPlaintextSize),
	}
	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			ciphertext, symbols := mustEncrypt(t, plaintext, testPassphrase)
			got, err := Decrypt(ciphertext, symbols, testPassphrase)
			if err != nil {
				t.Fatalf("Decrypt returned an unexpected error: %v", err)
			}
			if got != plaintext {
				t.Fatalf("round-trip mismatch for case %q", name)
			}
		})
	}
}

func TestWrongSymbol(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "secret", testPassphrase)

	altered := append([]string(nil), symbols...)
	altered[7] = symbolOutsideKey(t, symbols)

	if _, err := Decrypt(ciphertext, altered, testPassphrase); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestWrongSymbolOrder(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "secret", testPassphrase)

	shuffled := append([]string(nil), symbols...)
	shuffled[0], shuffled[1] = shuffled[1], shuffled[0]

	if _, err := Decrypt(ciphertext, shuffled, testPassphrase); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestWrongPassphrase(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "secret", testPassphrase)

	if _, err := Decrypt(ciphertext, symbols, testPassphrase+"!"); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestWrongSymbolCount(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "secret", testPassphrase)

	tooFew := symbols[:KeySize-1]
	tooMany := append(append([]string(nil), symbols...), symbolOutsideKey(t, symbols))

	for name, candidate := range map[string][]string{"tooFew": tooFew, "tooMany": tooMany} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decrypt(ciphertext, candidate, testPassphrase); !errors.Is(err, ErrInvalidSymbols) {
				t.Fatalf("expected ErrInvalidSymbols, got %v", err)
			}
		})
	}
}

func TestDuplicateSymbol(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "secret", testPassphrase)

	duplicated := append([]string(nil), symbols...)
	duplicated[5] = duplicated[6]

	if _, err := Decrypt(ciphertext, duplicated, testPassphrase); !errors.Is(err, ErrInvalidSymbols) {
		t.Fatalf("expected ErrInvalidSymbols, got %v", err)
	}
}

func TestSymbolOutsideTable(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "secret", testPassphrase)

	foreign := append([]string(nil), symbols...)
	foreign[3] = "❤"

	if _, err := Decrypt(ciphertext, foreign, testPassphrase); !errors.Is(err, ErrInvalidSymbols) {
		t.Fatalf("expected ErrInvalidSymbols, got %v", err)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, strings.Repeat("payload ", 32), testPassphrase)

	body := []byte(ciphertext[len(payloadPrefix):])
	middle := len(body) / 2
	if body[middle] == 'A' {
		body[middle] = 'B'
	} else {
		body[middle] = 'A'
	}
	tampered := payloadPrefix + string(body)

	_, err := Decrypt(tampered, symbols, testPassphrase)
	if !errors.Is(err, ErrAuthFailed) && !errors.Is(err, ErrCorruptData) {
		t.Fatalf("expected ErrAuthFailed or ErrCorruptData, got %v", err)
	}
}

func TestTamperedPayloadRegions(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "region tampering", testPassphrase)

	regions := map[string]int{
		"salt":     0,
		"nonce":    saltSize,
		"checksum": saltSize + nonceSize,
		"sealed":   headerSize,
	}
	for name, offset := range regions {
		t.Run(name, func(t *testing.T) {
			p, err := decodePayload(ciphertext)
			if err != nil {
				t.Fatalf("decodePayload returned an unexpected error: %v", err)
			}
			raw := make([]byte, 0, headerSize+len(p.sealed))
			raw = append(raw, p.salt...)
			raw = append(raw, p.nonce...)
			raw = append(raw, p.checksum...)
			raw = append(raw, p.sealed...)
			raw[offset] ^= 0xFF

			tampered := (&payload{
				salt:     raw[:saltSize],
				nonce:    raw[saltSize : saltSize+nonceSize],
				checksum: raw[saltSize+nonceSize : headerSize],
				sealed:   raw[headerSize:],
			}).encode()

			if _, err := Decrypt(tampered, symbols, testPassphrase); !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("expected ErrAuthFailed, got %v", err)
			}
		})
	}
}

func TestTamperedVersionPrefix(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "secret", testPassphrase)

	tampered := "zc2:" + ciphertext[len(payloadPrefix):]
	if _, err := Decrypt(tampered, symbols, testPassphrase); !errors.Is(err, ErrCorruptData) {
		t.Fatalf("expected ErrCorruptData, got %v", err)
	}
}

func TestGCMRejectsAADMismatch(t *testing.T) {
	encKey := make([]byte, encKeySize)
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatalf("rand.Read returned an unexpected error: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read returned an unexpected error: %v", err)
	}

	sealed, err := sealPayload(encKey, nonce, []byte("aad bound plaintext"), payloadAAD)
	if err != nil {
		t.Fatalf("sealPayload returned an unexpected error: %v", err)
	}

	if _, err := openPayload(encKey, nonce, sealed, []byte("zc2")); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed on AAD mismatch, got %v", err)
	}
	if _, err := openPayload(encKey, nonce, sealed, payloadAAD); err != nil {
		t.Fatalf("expected success with the matching AAD, got %v", err)
	}
}

func TestInvalidBase64(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "secret", testPassphrase)

	body := []byte(ciphertext[len(payloadPrefix):])
	body[len(body)/2] = '!'
	tampered := payloadPrefix + string(body)

	if _, err := Decrypt(tampered, symbols, testPassphrase); !errors.Is(err, ErrCorruptData) {
		t.Fatalf("expected ErrCorruptData, got %v", err)
	}
}

func TestShortPayload(t *testing.T) {
	_, symbols := mustEncrypt(t, "secret", testPassphrase)

	short := (&payload{
		salt:     make([]byte, saltSize),
		nonce:    make([]byte, nonceSize),
		checksum: make([]byte, checksumSize-1),
	}).encode()

	if _, err := Decrypt(short, symbols, testPassphrase); !errors.Is(err, ErrCorruptData) {
		t.Fatalf("expected ErrCorruptData, got %v", err)
	}
}

func TestOversizedInput(t *testing.T) {
	oversized := strings.Repeat("x", MaxPlaintextSize+1)

	start := time.Now()
	_, _, err := Encrypt(oversized, testPassphrase)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("expected ErrInputTooLarge, got %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("size rejection took %v, which suggests key derivation ran", elapsed)
	}
}

func TestSymbolTableIntegrity(t *testing.T) {
	table := SymbolTable()
	if len(table) != TableSize {
		t.Fatalf("expected %d symbols, got %d", TableSize, len(table))
	}

	seen := make(map[string]bool, TableSize)
	for i, symbol := range table {
		if seen[symbol] {
			t.Fatalf("symbol at index %d is a duplicate", i)
		}
		seen[symbol] = true

		if utf8.RuneCountInString(symbol) != 1 {
			t.Fatalf("symbol at index %d is not a single codepoint", i)
		}
		if !norm.NFC.IsNormalString(symbol) {
			t.Fatalf("symbol at index %d is not NFC-normalized", i)
		}
	}
}

func TestGenerateProducesDistinctSymbols(t *testing.T) {
	for i := 0; i < 64; i++ {
		symbols, indices, err := defaultTable.generate(rand.Reader)
		if err != nil {
			t.Fatalf("generate returned an unexpected error: %v", err)
		}
		if len(symbols) != KeySize || len(indices) != KeySize {
			t.Fatalf("expected %d symbols and indices, got %d and %d", KeySize, len(symbols), len(indices))
		}
		if _, err := defaultTable.indices(symbols); err != nil {
			t.Fatalf("generated symbols failed validation: %v", err)
		}
	}
}

func TestFixedVector(t *testing.T) {
	salt := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	nonce := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B}

	indices := make([]byte, KeySize)
	for i := range indices {
		indices[i] = byte(i)
	}

	const (
		plaintext  = "zodiac crypto fixed test vector"
		passphrase = "fixed-vector-passphrase"
		want       = fixedVectorCiphertext
	)

	got, err := encryptWith(plaintext, passphrase, indices, salt, nonce)
	if err != nil {
		t.Fatalf("encryptWith returned an unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("cryptographic behaviour changed\n want: %s\n  got: %s", want, got)
	}

	decrypted, err := Decrypt(got, symbolsFromIndices(indices), passphrase)
	if err != nil {
		t.Fatalf("Decrypt returned an unexpected error: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("expected plaintext %q, got %q", plaintext, decrypted)
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	symbols, _, err := defaultTable.generate(rand.Reader)
	if err != nil {
		t.Fatalf("generate returned an unexpected error: %v", err)
	}

	parsed, err := ParseSymbols(FormatSymbols(symbols))
	if err != nil {
		t.Fatalf("ParseSymbols returned an unexpected error: %v", err)
	}
	if len(parsed) != len(symbols) {
		t.Fatalf("expected %d symbols, got %d", len(symbols), len(parsed))
	}
	for i := range symbols {
		if parsed[i] != symbols[i] {
			t.Fatalf("symbol %d changed: expected %q, got %q", i, symbols[i], parsed[i])
		}
	}
}

func TestWhitespaceTolerantParsing(t *testing.T) {
	ciphertext, symbols := mustEncrypt(t, "whitespace tolerant", testPassphrase)
	clean := FormatSymbols(symbols)

	messy := map[string]string{
		"doubleSpaces":    strings.Join(symbols, "  "),
		"tabs":            strings.Join(symbols, "\t"),
		"mixedRuns":       strings.Join(symbols, " \t  \n "),
		"surroundedSpace": "  \t\n" + clean + "\n\t  ",
		"nonBreakingRun":  strings.Join(symbols, "  "),
	}

	expected, err := ParseSymbols(clean)
	if err != nil {
		t.Fatalf("ParseSymbols returned an unexpected error: %v", err)
	}

	for name, variant := range messy {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseSymbols(variant)
			if err != nil {
				t.Fatalf("ParseSymbols returned an unexpected error: %v", err)
			}
			if len(parsed) != len(expected) {
				t.Fatalf("expected %d symbols, got %d", len(expected), len(parsed))
			}
			for i := range expected {
				if parsed[i] != expected[i] {
					t.Fatalf("symbol %d changed: expected %q, got %q", i, expected[i], parsed[i])
				}
			}
			got, err := Decrypt(ciphertext, parsed, testPassphrase)
			if err != nil {
				t.Fatalf("Decrypt returned an unexpected error: %v", err)
			}
			if got != "whitespace tolerant" {
				t.Fatalf("expected plaintext %q, got %q", "whitespace tolerant", got)
			}
		})
	}
}

func TestConcurrentEncryptDecrypt(t *testing.T) {
	const workers = 4

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			plaintext := strings.Repeat("concurrent", worker+1)
			ciphertext, symbols, err := Encrypt(plaintext, testPassphrase)
			if err != nil {
				t.Errorf("worker %d: Encrypt returned an unexpected error: %v", worker, err)
				return
			}
			got, err := Decrypt(ciphertext, symbols, testPassphrase)
			if err != nil {
				t.Errorf("worker %d: Decrypt returned an unexpected error: %v", worker, err)
				return
			}
			if got != plaintext {
				t.Errorf("worker %d: round-trip mismatch", worker)
			}
		}(i)
	}
	wg.Wait()
}
