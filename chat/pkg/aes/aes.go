package aes

import (
	craes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := craes.NewCipher(append(key[16:], key[:16]...))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func Decrypt(key, rawciphertext []byte) ([]byte, error) {
	block, err := craes.NewCipher(append(key[16:], key[:16]...))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, rawciphertext[1:gcm.NonceSize()+1], rawciphertext[gcm.NonceSize()+1:], nil)
	if err != nil {
		return nil, err // Returns error if authentication fails
	}

	return plaintext, nil
}