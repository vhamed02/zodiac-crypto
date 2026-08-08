package main

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"

	zodiaccrypto "github.com/vhamed02/zodiac-crypto"
)

type scriptedPrompter struct {
	lines     []string
	passwords []string
}

func (p *scriptedPrompter) Line(string) (string, error) {
	if len(p.lines) == 0 {
		return "", errors.New("no scripted line left")
	}
	line := p.lines[0]
	p.lines = p.lines[1:]
	return line, nil
}

func (p *scriptedPrompter) Password(string) (string, error) {
	if len(p.passwords) == 0 {
		return "", errors.New("no scripted passphrase left")
	}
	password := p.passwords[0]
	p.passwords = p.passwords[1:]
	return password, nil
}

func newStreams(stdin string) (*streams, *bytes.Buffer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	return &streams{in: bufio.NewReader(strings.NewReader(stdin)), out: out, err: errOut}, out, errOut
}

func encryptViaCLI(t *testing.T, plaintext, passphrase string) (string, string) {
	t.Helper()

	s, out, _ := newStreams(plaintext)
	prompter := &scriptedPrompter{passwords: []string{passphrase}}
	if err := run([]string{"encrypt"}, s, prompter); err != nil {
		t.Fatalf("encrypt returned an unexpected error: %v", err)
	}

	ciphertext, symbolLine := parseEncryptOutput(t, out.String())
	return ciphertext, symbolLine
}

func parseEncryptOutput(t *testing.T, output string) (string, string) {
	t.Helper()

	var ciphertext, symbolLine string
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "zc1:"):
			ciphertext = line
		case strings.HasPrefix(line, "Recovery symbols"):
			if i+1 >= len(lines) {
				t.Fatalf("recovery symbols label is not followed by a symbol line:\n%s", output)
			}
			symbolLine = lines[i+1]
		}
	}
	if ciphertext == "" || symbolLine == "" {
		t.Fatalf("encrypt output is missing the ciphertext or the symbols:\n%s", output)
	}
	if !strings.Contains(output, "WARNING") {
		t.Fatalf("encrypt output is missing the one-time key warning:\n%s", output)
	}
	return ciphertext, symbolLine
}

func TestCLIRoundTrip(t *testing.T) {
	const plaintext = "cli round trip payload"
	const passphrase = "cli-passphrase"

	ciphertext, symbolLine := encryptViaCLI(t, plaintext, passphrase)

	s, out, _ := newStreams(ciphertext + "\n")
	prompter := &scriptedPrompter{lines: []string{symbolLine}, passwords: []string{passphrase}}
	if err := run([]string{"decrypt"}, s, prompter); err != nil {
		t.Fatalf("decrypt returned an unexpected error: %v", err)
	}
	if out.String() != plaintext {
		t.Fatalf("expected plaintext %q, got %q", plaintext, out.String())
	}
}

func TestCLIDecryptWithInputFlag(t *testing.T) {
	const plaintext = "input flag payload"
	const passphrase = "cli-passphrase"

	ciphertext, symbolLine := encryptViaCLI(t, plaintext, passphrase)

	s, out, _ := newStreams("")
	prompter := &scriptedPrompter{lines: []string{symbolLine}, passwords: []string{passphrase}}
	if err := run([]string{"decrypt", "--input", ciphertext}, s, prompter); err != nil {
		t.Fatalf("decrypt returned an unexpected error: %v", err)
	}
	if out.String() != plaintext {
		t.Fatalf("expected plaintext %q, got %q", plaintext, out.String())
	}
}

func TestCLIPassphraseFromStdin(t *testing.T) {
	const plaintext = "piped passphrase payload"
	const passphrase = "piped-passphrase"

	s, out, _ := newStreams(passphrase + "\n" + plaintext)
	if err := run([]string{"encrypt", "--passphrase-stdin"}, s, &scriptedPrompter{}); err != nil {
		t.Fatalf("encrypt returned an unexpected error: %v", err)
	}
	ciphertext, symbolLine := parseEncryptOutput(t, out.String())

	decryptStreams, decryptOut, _ := newStreams(ciphertext + "\n" + passphrase + "\n")
	prompter := &scriptedPrompter{lines: []string{symbolLine}}
	if err := run([]string{"decrypt", "--passphrase-stdin"}, decryptStreams, prompter); err != nil {
		t.Fatalf("decrypt returned an unexpected error: %v", err)
	}
	if decryptOut.String() != plaintext {
		t.Fatalf("expected plaintext %q, got %q", plaintext, decryptOut.String())
	}
}

func TestCLIDecryptToleratesPastedWhitespace(t *testing.T) {
	const plaintext = "whitespace tolerant cli payload"
	const passphrase = "cli-passphrase"

	ciphertext, symbolLine := encryptViaCLI(t, plaintext, passphrase)
	symbols := strings.Fields(symbolLine)

	variants := map[string]string{
		"doubleSpaces":  strings.Join(symbols, "  "),
		"tabs":          strings.Join(symbols, "\t"),
		"trailingSpace": "  " + strings.Join(symbols, " ") + " \t\n",
	}

	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			s, out, _ := newStreams(ciphertext + "\n")
			prompter := &scriptedPrompter{lines: []string{variant}, passwords: []string{passphrase}}
			if err := run([]string{"decrypt"}, s, prompter); err != nil {
				t.Fatalf("decrypt returned an unexpected error: %v", err)
			}
			if out.String() != plaintext {
				t.Fatalf("expected plaintext %q, got %q", plaintext, out.String())
			}
		})
	}
}

func TestCLIDecryptWrongPassphrase(t *testing.T) {
	ciphertext, symbolLine := encryptViaCLI(t, "secret", "cli-passphrase")

	s, _, _ := newStreams(ciphertext + "\n")
	prompter := &scriptedPrompter{lines: []string{symbolLine}, passwords: []string{"wrong"}}

	err := run([]string{"decrypt"}, s, prompter)
	if !errors.Is(err, zodiaccrypto.ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestCLIDecryptInvalidSymbols(t *testing.T) {
	ciphertext, _ := encryptViaCLI(t, "secret", "cli-passphrase")

	s, _, _ := newStreams(ciphertext + "\n")
	prompter := &scriptedPrompter{lines: []string{"○ ● △"}, passwords: []string{"cli-passphrase"}}

	err := run([]string{"decrypt"}, s, prompter)
	if !errors.Is(err, zodiaccrypto.ErrInvalidSymbols) {
		t.Fatalf("expected ErrInvalidSymbols, got %v", err)
	}
}

func TestCLIDecryptCorruptCiphertext(t *testing.T) {
	_, symbolLine := encryptViaCLI(t, "secret", "cli-passphrase")

	s, _, _ := newStreams("not-a-ciphertext\n")
	prompter := &scriptedPrompter{lines: []string{symbolLine}, passwords: []string{"cli-passphrase"}}

	err := run([]string{"decrypt"}, s, prompter)
	if !errors.Is(err, zodiaccrypto.ErrCorruptData) {
		t.Fatalf("expected ErrCorruptData, got %v", err)
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	s, _, errOut := newStreams("")
	if err := run([]string{"sign"}, s, &scriptedPrompter{}); err == nil {
		t.Fatal("expected an error for an unknown command")
	}
	if !strings.Contains(errOut.String(), "Usage:") {
		t.Fatalf("expected the usage text on stderr, got %q", errOut.String())
	}
}
