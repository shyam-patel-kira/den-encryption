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
	// Define the secret message and user-provided encryption key
	secretMessage := "my secret message"
	userKey := "mySecret"

	// Convert the user-provided key to a 32-byte key using SHA-256
	encryptionKey := generateAESKey(userKey)

	// Encrypt the message
	encryptedMessage, err := encryptAES(secretMessage, encryptionKey)
	if err != nil {
		panic(err)
	}

	// Load an image to hide the encrypted message
	sourceImage, err := loadImageFromFile("./lena.png")
	if err != nil {
		panic(err)
	}

	// Embed the encrypted message into the image
	err = embedMessageInImage(sourceImage, encryptedMessage, "output.png")
	if err != nil {
		panic(err)
	}

	// Extract the encrypted message from the image
	extractedMessage, err := extractMessageFromImage("output.png")
	if err != nil {
		panic(err)
	}

	// Decrypt the extracted message
	decryptedMessage, err := decryptAES(extractedMessage, encryptionKey)
	if err != nil {
		panic(err)
	}

	println("Decrypted text:", decryptedMessage)
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

// embedMessageInImage embeds encrypted text into an image and saves the result.
func embedMessageInImage(img image.Image, message []byte, outputPath string) error {
	// Convert the input image to an *image.NRGBA which is suitable for the steganography.Encode function
	bounds := img.Bounds()
	nrgbaImage := image.NewNRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			nrgbaImage.Set(x, y, img.At(x, y))
		}
	}

	writeBuffer := new(bytes.Buffer)
	// Encode the message into the image
	if err := steganography.Encode(writeBuffer, nrgbaImage, message); err != nil {
		return err
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Write the buffer content to the output file
	_, err = writeBuffer.WriteTo(outputFile)
	return err
}

// extractMessageFromImage retrieves encrypted text from an image file.
func extractMessageFromImage(filePath string) ([]byte, error) {
	imgFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer imgFile.Close()

	img, err := png.Decode(imgFile)
	if err != nil {
		return nil, err
	}

	// Determine the size of the hidden message
	sizeOfMessage := steganography.GetMessageSizeFromImage(img)

	// Decode the message from the image
	message := steganography.Decode(sizeOfMessage, img)
	return message, nil
}
