package zodiaccrypto

import "errors"

var (
	ErrInvalidSymbols = errors.New("invalid symbol sequence: must be exactly 32 distinct symbols from the valid table")
	ErrAuthFailed     = errors.New("authentication failed: wrong symbols, passphrase, or tampered data")
	ErrCorruptData    = errors.New("corrupt or malformed ciphertext")
	ErrInputTooLarge  = errors.New("plaintext exceeds maximum allowed size (10MB)")
)
