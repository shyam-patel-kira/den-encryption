package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"image"
	"image/png"
	"io/ioutil"
	"os"

	"github.com/auyer/steganography"
)

func main() {
	// Define the secret message and user-provided encryption keys
	secretMessages := []string{"decoyee secret message", "my actual Secret message"}
	userKeys := []string{"mySecret1", "mySecret2"}

	// Convert the user-provided keys to 32-byte keys using SHA-256
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
	sourceImage, err := loadImageFromFile("/Users/shyampatel/Networking/random/den-cryption/lena.png")
	if err != nil {
		panic(fmt.Sprintf("Failed to load image: %v", err))
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
	decryptionKey1 := generateAESKey(userKeys[0]) // Using the second key
	decryptedMessage1, err := decryptAES(extractedMessages[0], decryptionKey1)
	if err != nil {
		panic(err)
	}
	// Decrypt the second message as an example
	decryptionKey2 := generateAESKey(userKeys[1]) // Using the second key
	decryptedMessage2, err := decryptAES(extractedMessages[1], decryptionKey2)
	if err != nil {
		panic(err)
	}

	println("Decrypted text with key 1:", decryptedMessage1)
	println("Decrypted text with key 2:", decryptedMessage2)
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
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	// Read file bytes directly for debugging
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file bytes: %v", err)
	}

	// Decode the image from the byte slice
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error decoding PNG: %v", err)
	}
	return img, nil
}

// embedMessagesInImage embeds multiple encrypted texts into an image and saves the result.
func embedMessagesInImage(img image.Image, messages [][]byte, outputPath string) error {
	bounds := img.Bounds()
	nrgbaImage := image.NewNRGBA(bounds)

	// Copying the original image to the new image format
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			nrgbaImage.Set(x, y, img.At(x, y))
		}
	}

	writeBuffer := new(bytes.Buffer)
	combinedMessage := bytes.Join(messages, []byte("|")) // Combine messages with delimiter

	// Encoding the combined message into the nrgbaImage
	if err := steganography.Encode(writeBuffer, nrgbaImage, combinedMessage); err != nil {
		return fmt.Errorf("error encoding message into image: %v", err)
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Writing the buffer content to the output file as PNG
	if _, err = outputFile.Write(writeBuffer.Bytes()); err != nil {
		return fmt.Errorf("error writing to output file: %v", err)
	}

	return nil
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
