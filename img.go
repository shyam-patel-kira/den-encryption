package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"image"
	"image/png"
	"os"

	"github.com/auyer/steganography"
)

func main() {
	// Define secret messages and user-provided encryption keys
	secretMessages := []string{"my secret message 1", "another secret message"}
	userKeys := []string{"mySecret1", "mySecret2"}

	// Convert user-provided keys to 32-byte keys using SHA-256 and encrypt messages
	encryptedMessages := [][]byte{}
	for i, key := range userKeys {
		encryptionKey := generateAESKey(key)
		encryptedMessage, err := encryptAES(secretMessages[i], encryptionKey)
		if err != nil {
			panic(err)
		}
		encryptedMessages = append(encryptedMessages, encryptedMessage)
	}

	// Load an image to hide the encrypted messages
	sourceImage, err := loadImageFromFile("./lena.png")
	if err != nil {
		panic(err)
	}

	// Embed all encrypted messages into the image
	err = embedMessagesInImage(sourceImage, encryptedMessages, "output.png")
	if err != nil {
		panic(err)
	}

	// Extract and decrypt messages using the second key for demonstration
	extractedMessages, err := extractMessagesFromImage("output.png", len(userKeys))
	if err != nil {
		panic(err)
	}

	// Decrypt the second message as an example
	decryptionKey := generateAESKey(userKeys[1]) // Using the second key
	decryptedMessage, err := decryptAES(extractedMessages[1], decryptionKey)
	if err != nil {
		panic(err)
	}

	println("Decrypted text with key 2:", decryptedMessage)
}

// generateAESKey creates a 32-byte AES key from any given string using SHA-256 hashing.
func generateAESKey(inputKey string) []byte {
	hash := sha256.Sum256([]byte(inputKey))
	return hash[:]
}

// encryptAES encrypts plaintext using AES encryption with the provided key.
func encryptAES(plaintext string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, key[:aes.BlockSize])
	encryptedText := make([]byte, len(plaintext))
	cfb.XORKeyStream(encryptedText, []byte(plaintext))

	return encryptedText, nil
}

// decryptAES decrypts ciphertext using AES decryption with the provided key.
func decryptAES(ciphertext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cfb := cipher.NewCFBDecrypter(block, key[:aes.BlockSize])
	decryptedText := make([]byte, len(ciphertext))
	cfb.XORKeyStream(decryptedText, ciphertext)

	return string(decryptedText), nil
}

// loadImageFromFile loads an image from the specified file path.
func loadImageFromFile(filePath string) (image.Image, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return png.Decode(file)
}

// embedMessagesInImage embeds multiple encrypted texts into an image and saves the result.
func embedMessagesInImage(img image.Image, messages [][]byte, outputPath string) error {
	bounds := img.Bounds()
	nrgbaImage := image.NewNRGBA(bounds)
	writeBuffer := new(bytes.Buffer)

	// Combine messages with a delimiter or fixed size blocks if messages are guaranteed to be the same length
	for _, msg := range messages {
		if _, err := writeBuffer.Write(msg); err != nil {
			return err
		}
		// Write a delimiter if needed
		if _, err := writeBuffer.Write([]byte("|")); err != nil {
			return err
		}
	}

	if err := steganography.Encode(writeBuffer, nrgbaImage, writeBuffer.Bytes()); err != nil {
		return err
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	_, err = writeBuffer.WriteTo(outputFile)
	return err
}

// extractMessagesFromImage retrieves multiple encrypted texts from an image file based on the count of keys/messages.
func extractMessagesFromImage(filePath string, count int) ([][]byte, error) {
	imgFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer imgFile.Close()

	img, err := png.Decode(imgFile)
	if err != nil {
		return nil, err
	}

	sizeOfMessage := steganography.GetMessageSizeFromImage(img)
	encodedData := steganography.Decode(sizeOfMessage, img)

	// Split messages using the delimiter or fixed size blocks
	return bytes.SplitN(encodedData, []byte("|"), count), nil
}
