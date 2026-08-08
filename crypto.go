package zodiaccrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	versionPrefix = "zc1"
	payloadPrefix = versionPrefix + ":"

	saltSize     = 16
	nonceSize    = 12
	checksumSize = 8
	headerSize   = saltSize + nonceSize + checksumSize

	MaxPlaintextSize = 10 * 1024 * 1024

	argon2Time    = 3
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	masterKeySize = 32

	encKeySize = 32
	macKeySize = 16

	encKeyInfo = "zodiac-crypto-v1-enc"
	macKeyInfo = "zodiac-crypto-v1-checksum"

	decryptDelay = 150 * time.Millisecond
)

var payloadAAD = []byte(versionPrefix)

type derivedKeys struct {
	enc []byte
	mac []byte
}

func (k *derivedKeys) destroy() {
	zero(k.enc)
	zero(k.mac)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("random source failure: %w", err)
	}
	return b, nil
}

func deriveKeys(indices []byte, passphrase string, salt []byte) (*derivedKeys, error) {
	secret := make([]byte, 0, len(indices)+len(passphrase))
	secret = append(secret, indices...)
	secret = append(secret, passphrase...)
	defer zero(secret)

	master := argon2.IDKey(secret, salt, argon2Time, argon2Memory, argon2Threads, masterKeySize)
	defer zero(master)

	enc, err := expandKey(master, encKeyInfo, encKeySize)
	if err != nil {
		return nil, err
	}
	mac, err := expandKey(master, macKeyInfo, macKeySize)
	if err != nil {
		zero(enc)
		return nil, err
	}
	return &derivedKeys{enc: enc, mac: mac}, nil
}

func expandKey(master []byte, info string, size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, []byte(info)), key); err != nil {
		return nil, fmt.Errorf("key expansion failed: %w", err)
	}
	return key, nil
}

func computeChecksum(macKey, salt, nonce []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(salt)
	mac.Write(nonce)
	return mac.Sum(nil)[:checksumSize]
}

func newGCM(encKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("cipher initialization failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm initialization failed: %w", err)
	}
	return gcm, nil
}

func sealPayload(encKey, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(encKey)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func openPayload(encKey, nonce, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(encKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return plaintext, nil
}

type payload struct {
	salt     []byte
	nonce    []byte
	checksum []byte
	sealed   []byte
}

func (p *payload) encode() string {
	raw := make([]byte, 0, headerSize+len(p.sealed))
	raw = append(raw, p.salt...)
	raw = append(raw, p.nonce...)
	raw = append(raw, p.checksum...)
	raw = append(raw, p.sealed...)
	return payloadPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func decodePayload(ciphertext string) (*payload, error) {
	trimmed := strings.TrimSpace(ciphertext)
	if !strings.HasPrefix(trimmed, payloadPrefix) {
		return nil, fmt.Errorf("missing %q version prefix: %w", payloadPrefix, ErrCorruptData)
	}
	raw, err := base64.RawURLEncoding.DecodeString(trimmed[len(payloadPrefix):])
	if err != nil {
		return nil, fmt.Errorf("payload is not valid base64url: %w", ErrCorruptData)
	}
	if len(raw) < headerSize {
		return nil, fmt.Errorf("payload is shorter than %d bytes: %w", headerSize, ErrCorruptData)
	}
	return &payload{
		salt:     raw[:saltSize],
		nonce:    raw[saltSize : saltSize+nonceSize],
		checksum: raw[saltSize+nonceSize : headerSize],
		sealed:   raw[headerSize:],
	}, nil
}

func encryptWith(plaintext, passphrase string, indices, salt, nonce []byte) (string, error) {
	keys, err := deriveKeys(indices, passphrase, salt)
	if err != nil {
		return "", err
	}
	defer keys.destroy()

	sealed, err := sealPayload(keys.enc, nonce, []byte(plaintext), payloadAAD)
	if err != nil {
		return "", err
	}
	encoded := &payload{
		salt:     salt,
		nonce:    nonce,
		checksum: computeChecksum(keys.mac, salt, nonce),
		sealed:   sealed,
	}
	return encoded.encode(), nil
}

func decryptWith(p *payload, indices []byte, passphrase string) (string, error) {
	keys, err := deriveKeys(indices, passphrase, p.salt)
	if err != nil {
		return "", err
	}
	defer keys.destroy()

	if subtle.ConstantTimeCompare(computeChecksum(keys.mac, p.salt, p.nonce), p.checksum) != 1 {
		return "", ErrAuthFailed
	}
	plaintext, err := openPayload(keys.enc, p.nonce, p.sealed, payloadAAD)
	if err != nil {
		return "", err
	}
	defer zero(plaintext)
	return string(plaintext), nil
}
