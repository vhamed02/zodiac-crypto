package zodiaccrypto

import (
	"crypto/rand"
	"time"
)

func Encrypt(plaintext string, passphrase string) (string, []string, error) {
	if len(plaintext) > MaxPlaintextSize {
		return "", nil, ErrInputTooLarge
	}
	symbols, indices, err := defaultTable.generate(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	defer zero(indices)

	salt, err := randomBytes(saltSize)
	if err != nil {
		return "", nil, err
	}
	nonce, err := randomBytes(nonceSize)
	if err != nil {
		return "", nil, err
	}
	ciphertext, err := encryptWith(plaintext, passphrase, indices, salt, nonce)
	if err != nil {
		return "", nil, err
	}
	return ciphertext, symbols, nil
}

func Decrypt(ciphertext string, symbols []string, passphrase string) (string, error) {
	defer time.Sleep(decryptDelay)

	indices, err := defaultTable.indices(symbols)
	if err != nil {
		return "", err
	}
	defer zero(indices)

	p, err := decodePayload(ciphertext)
	if err != nil {
		return "", err
	}
	return decryptWith(p, indices, passphrase)
}
