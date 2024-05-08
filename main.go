package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

func createHash(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

func encrypt(data []byte, passphrase string) (string, error) {
	block, _ := aes.NewCipher(createHash(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func decrypt(encryptedString string, passphrase string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(encryptedString)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(createHash(passphrase))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func main() {
	realData := "Real secret"
	decoyData := "Decoy data"
	realPassword := "realKey123"
	decoyPassword := "decoyKey123"

	// Encrypt both segments
	encryptedReal, err := encrypt([]byte(realData), realPassword)
	if err != nil {
		fmt.Println(err)
		return
	}
	encryptedDecoy, err := encrypt([]byte(decoyData), decoyPassword)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Combine both encrypted data into one (for simplicity, just concatenate)
	combinedEncryptedData := encryptedReal + "||" + encryptedDecoy

	// Assume decryption attempt
	fmt.Println("Enter the password to decrypt the data:")
	var inputPassword string
	fmt.Scanln(&inputPassword)

	var decryptedData []byte
	// Split the combined data and attempt to decrypt based on input password
	parts := strings.Split(combinedEncryptedData, "||")
	for _, part := range parts {
		decryptedData, err = decrypt(part, inputPassword)
		if err == nil {
			fmt.Println("Decrypted data:", string(decryptedData))
			return
		}
	}

	fmt.Println("Failed to decrypt: incorrect password or data corrupted")
}
