package credentialstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/KLORQ/quarshell-core/domain"
)

type cipherBox struct {
	aead cipher.AEAD
}

func newCipherBox(key []byte) (*cipherBox, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, domain.Invalidf("credentials.store", "key must be 16, 24, or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, domain.Wrap(err, "credentials.store", "create cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, domain.Wrap(err, "credentials.store", "create gcm")
	}
	return &cipherBox{aead: aead}, nil
}

func (c *cipherBox) seal(material []byte) ([]byte, []byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, domain.Wrap(err, "credentials.store", "generate nonce")
	}
	return nonce, c.aead.Seal(nil, nonce, material, nil), nil
}

func (c *cipherBox) open(nonce, ciphertext []byte) ([]byte, error) {
	material, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, domain.Wrap(err, "credentials.store", "decrypt credential")
	}
	return material, nil
}
