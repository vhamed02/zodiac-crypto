package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	zodiaccrypto "github.com/vhamed02/zodiac-crypto"
	"golang.org/x/term"
)

const usage = `zodiaccrypto - symbol-key authenticated encryption

Usage:
  zodiaccrypto encrypt [--passphrase-stdin]
  zodiaccrypto decrypt [--input <ciphertext>] [--symbols <key>] [--passphrase-stdin]

encrypt reads the plaintext from stdin and prints the ciphertext together with
the randomly generated 32-symbol recovery key.

decrypt reads the ciphertext from --input or from the first line of stdin, then
asks for the symbol key and the passphrase on the terminal. Use --symbols and
--passphrase-stdin to supply them without prompting.

When no terminal is available, prompts fall back to stdin in this order:
  encrypt: passphrase (only with --passphrase-stdin), then plaintext
  decrypt: ciphertext (unless --input), symbol key, passphrase
`

const recoveryWarning = `WARNING: the recovery symbols above are shown only once and are not stored
anywhere. Save them now, in order, in a safe place. Without them the data is
permanently unrecoverable.`

type prompter interface {
	Line(prompt string) (string, error)
	Password(prompt string) (string, error)
}

type streams struct {
	in  *bufio.Reader
	out io.Writer
	err io.Writer
}

type ttyPrompter struct {
	tty    *os.File
	reader *bufio.Reader
}

func (p *ttyPrompter) Line(prompt string) (string, error) {
	fmt.Fprint(p.tty, prompt)
	return readLine(p.reader)
}

func (p *ttyPrompter) Password(prompt string) (string, error) {
	fmt.Fprint(p.tty, prompt)
	secret, err := term.ReadPassword(int(p.tty.Fd()))
	fmt.Fprintln(p.tty)
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	return string(secret), nil
}

type readerPrompter struct {
	reader *bufio.Reader
	notice io.Writer
}

func (p *readerPrompter) Line(prompt string) (string, error) {
	fmt.Fprint(p.notice, prompt)
	return readLine(p.reader)
}

func (p *readerPrompter) Password(prompt string) (string, error) {
	return p.Line(prompt)
}

func newPrompter(s *streams, stdin *os.File) (prompter, func()) {
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		if term.IsTerminal(int(tty.Fd())) {
			return &ttyPrompter{tty: tty, reader: bufio.NewReader(tty)}, func() { tty.Close() }
		}
		tty.Close()
	}
	if stdin != nil && term.IsTerminal(int(stdin.Fd())) {
		return &ttyPrompter{tty: stdin, reader: s.in}, func() {}
	}
	return &readerPrompter{reader: s.in, notice: s.err}, func() {}
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if line == "" && errors.Is(err, io.EOF) {
		return "", io.EOF
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func main() {
	s := &streams{in: bufio.NewReader(os.Stdin), out: os.Stdout, err: os.Stderr}
	p, closePrompter := newPrompter(s, os.Stdin)
	defer closePrompter()

	if err := run(os.Args[1:], s, p); err != nil {
		fmt.Fprintln(s.err, "error:", err)
		closePrompter()
		os.Exit(1)
	}
}

func run(args []string, s *streams, p prompter) error {
	if len(args) == 0 {
		fmt.Fprint(s.err, usage)
		return errors.New("no command given")
	}
	switch args[0] {
	case "encrypt":
		return runEncrypt(args[1:], s, p)
	case "decrypt":
		return runDecrypt(args[1:], s, p)
	case "help", "-h", "--help":
		fmt.Fprint(s.out, usage)
		return nil
	default:
		fmt.Fprint(s.err, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runEncrypt(args []string, s *streams, p prompter) error {
	flags := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	flags.SetOutput(s.err)
	passphraseStdin := flags.Bool("passphrase-stdin", false, "read the passphrase from the first line of stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}

	var passphrase string
	if *passphraseStdin {
		line, err := readLine(s.in)
		if err != nil {
			return fmt.Errorf("reading passphrase from stdin: %w", err)
		}
		passphrase = line
	}

	plaintext, err := io.ReadAll(s.in)
	if err != nil {
		return fmt.Errorf("reading plaintext: %w", err)
	}

	if !*passphraseStdin {
		passphrase, err = p.Password("Passphrase: ")
		if err != nil {
			return err
		}
	}

	ciphertext, symbols, err := zodiaccrypto.Encrypt(string(plaintext), passphrase)
	if err != nil {
		return userFacing(err)
	}

	fmt.Fprintln(s.out, "Ciphertext:")
	fmt.Fprintln(s.out, ciphertext)
	fmt.Fprintln(s.out)
	fmt.Fprintf(s.out, "Recovery symbols (%d):\n", len(symbols))
	fmt.Fprintln(s.out, zodiaccrypto.FormatSymbols(symbols))
	fmt.Fprintln(s.out)
	fmt.Fprintln(s.out, recoveryWarning)
	return nil
}

func runDecrypt(args []string, s *streams, p prompter) error {
	flags := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	flags.SetOutput(s.err)
	input := flags.String("input", "", "ciphertext to decrypt; read from stdin when empty")
	symbolFlag := flags.String("symbols", "", "32-symbol recovery key; prompted for when empty")
	passphraseStdin := flags.Bool("passphrase-stdin", false, "read the passphrase from stdin instead of prompting")
	if err := flags.Parse(args); err != nil {
		return err
	}

	ciphertext := strings.TrimSpace(*input)
	if ciphertext == "" {
		line, err := readLine(s.in)
		if err != nil {
			return fmt.Errorf("reading ciphertext: %w", err)
		}
		ciphertext = strings.TrimSpace(line)
	}
	if ciphertext == "" {
		return errors.New("no ciphertext given")
	}

	symbolLine := *symbolFlag
	if strings.TrimSpace(symbolLine) == "" {
		line, err := p.Line("Symbol key (32 symbols, space separated): ")
		if err != nil {
			return fmt.Errorf("reading symbol key: %w", err)
		}
		symbolLine = line
	}
	symbols, err := zodiaccrypto.ParseSymbols(symbolLine)
	if err != nil {
		return userFacing(err)
	}

	var passphrase string
	if *passphraseStdin {
		passphrase, err = readLine(s.in)
	} else {
		passphrase, err = p.Password("Passphrase: ")
	}
	if err != nil {
		return fmt.Errorf("reading passphrase: %w", err)
	}

	plaintext, err := zodiaccrypto.Decrypt(ciphertext, symbols, passphrase)
	if err != nil {
		return userFacing(err)
	}
	fmt.Fprint(s.out, plaintext)
	return nil
}

func userFacing(err error) error {
	for _, sentinel := range []error{
		zodiaccrypto.ErrAuthFailed,
		zodiaccrypto.ErrInvalidSymbols,
		zodiaccrypto.ErrCorruptData,
		zodiaccrypto.ErrInputTooLarge,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return err
}
