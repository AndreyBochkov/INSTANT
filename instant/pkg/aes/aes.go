package aes

import (
	"errors"
	"fmt"
	craes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

var (
	ZeroLengthCiphertextError = errors.New("Zero length ciphertext")
)

func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := craes.NewCipher(key)
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
	if len(rawciphertext) == 1 {
		return nil, ZeroLengthCiphertextError
	}
	
	if len(rawciphertext) <= 13 {
		return nil, errors.New(fmt.Sprintf("Too small rawciphertext: %x", rawciphertext))
	}

	block, err := craes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := rawciphertext[1:gcm.NonceSize()+1]
	ciphertext := rawciphertext[gcm.NonceSize()+1:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err // Returns error if authentication fails
	}

	return plaintext, nil
}