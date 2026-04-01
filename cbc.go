package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
)

// pkcs7Pad adds PKCS#7 padding to the data
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding from the data
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty data")
	}
	unpadding := int(data[length-1])
	if unpadding > length || unpadding == 0 {
		return nil, errors.New("invalid padding size")
	}
	for i := length - unpadding; i < length; i++ {
		if data[i] != byte(unpadding) {
			return nil, errors.New("invalid padding character")
		}
	}
	return data[:(length - unpadding)], nil
}

// CBCEncrypt encrypts plaintext using AES in CBC mode
// It returns IV + ciphertext
func CBCEncrypt(a *AES, plaintext []byte, iv []byte) ([]byte, error) {
	if len(iv) != 16 {
		return nil, fmt.Errorf("IV must be 16 bytes, got %d", len(iv))
	}

	padded := pkcs7Pad(plaintext, 16)
	ciphertext := make([]byte, len(padded))
	
	prevBlock := iv
	for i := 0; i < len(padded); i += 16 {
		block := padded[i : i+16]
		
		// XOR with previous block (or IV)
		xorBlock := make([]byte, 16)
		for j := 0; j < 16; j++ {
			xorBlock[j] = block[j] ^ prevBlock[j]
		}
		
		// Encrypt
		encryptedBlock := a.Encrypt(xorBlock)
		copy(ciphertext[i:i+16], encryptedBlock)
		
		prevBlock = encryptedBlock
	}

	// Prepend IV to ciphertext
	result := append(iv, ciphertext...)
	return result, nil
}

// CBCDecrypt decrypts ciphertext using AES in CBC mode
func CBCDecrypt(a *AES, data []byte) ([]byte, error) {
	if len(data) < 32 { // 16 bytes IV + at least 16 bytes block
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:16]
	ciphertext := data[16:]

	if len(ciphertext)%16 != 0 {
		return nil, errors.New("ciphertext is not a multiple of 16")
	}

	plaintext := make([]byte, len(ciphertext))
	prevBlock := iv

	for i := 0; i < len(ciphertext); i += 16 {
		block := ciphertext[i : i+16]
		
		// Decrypt block
		decryptedBlock := a.Decrypt(block)
		
		// XOR with previous block (or IV)
		for j := 0; j < 16; j++ {
			plaintext[i+j] = decryptedBlock[j] ^ prevBlock[j]
		}
		
		prevBlock = block
	}

	// Remove padding
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}

// GenerateRandomIV generates a random 16-byte initialization vector
func GenerateRandomIV() ([]byte, error) {
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	return iv, err
}
