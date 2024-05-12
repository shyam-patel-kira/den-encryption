package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"os"

	"github.com/auyer/steganography"
)

func main() {
	secretMessages := []string{"decoyee secret2", "actual secret 2"}
	userKeys := []string{"mySecret123", "mySecret234"}

	encryptedMessages := make([][]byte, len(secretMessages))
	for i, key := range userKeys {
		encryptionKey := generateAESKey(key)
		encryptedMessage, err := encryptAES(secretMessages[i], encryptionKey)
		if err != nil {
			panic(err)
		}
		encryptedMessages[i] = encryptedMessage
	}

	sourceImage, err := loadImageFromFile("lena.png")
	if err != nil {
		panic(fmt.Sprintf("Failed to load image: %v", err))
	}

	if err := embedMessagesInImage(sourceImage, encryptedMessages, "output.png"); err != nil {
		panic(err)
	}

	extractedMessages, err := extractMessagesFromImage("output.png", len(userKeys), encryptedMessages)
	if err != nil {
		panic(err)
	}

	for idx, extractedMessage := range extractedMessages {
		decryptionKey := generateAESKey(userKeys[idx])
		decryptedMessage, err := decryptAES(extractedMessage, decryptionKey)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Decrypted text with key %d: %s\n", idx+1, decryptedMessage)
	}
}

func generateAESKey(inputKey string) []byte {
	hash := sha256.Sum256([]byte(inputKey))
	return hash[:]
}

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

func loadImageFromFile(filePath string) (image.Image, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	img, err := png.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("error decoding PNG: %v", err)
	}
	return img, nil
}

func embedMessagesInImage(img image.Image, messages [][]byte, outputPath string) error {
	bounds := img.Bounds()
	nrgbaImage := image.NewNRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			nrgbaImage.Set(x, y, img.At(x, y))
		}
	}

	buf := new(bytes.Buffer)
	for _, msg := range messages {
		binary.Write(buf, binary.LittleEndian, int32(len(msg))) // Write message length
		buf.Write(msg)                                          // Write message content
	}

	// Encode using steganography library (v1.0.2)
	outputBuffer := new(bytes.Buffer)
	if err := steganography.Encode(outputBuffer, nrgbaImage, buf.Bytes()); err != nil {
		return fmt.Errorf("error encoding messages into image: %v", err)
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Write the modified image data from outputBuffer
	_, err = outputFile.Write(outputBuffer.Bytes())
	if err != nil {
		return fmt.Errorf("error writing to output file: %v", err)
	}

	return nil // No need for png.Encode here, we've already written the encoded data
}

// extractMessagesFromImage retrieves multiple encrypted texts from an image file based on the count of keys/messages.
func extractMessagesFromImage(filePath string, count int, encryptedMessages [][]byte) ([][]byte, error) {
	imgFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer imgFile.Close()

	img, err := png.Decode(imgFile)
	if err != nil {
		return nil, err
	}

	// Calculate the total size of encoded data
	totalSize := calculateTotalEncodedSize(encryptedMessages)

	// Decode the embedded data using steganography (v1.0.2)
	extractedData := steganography.Decode(totalSize, img) // No error returned

	// Extract individual messages based on their encoded lengths
	messages := make([][]byte, 0, count)
	dataReader := bytes.NewReader(extractedData)
	for i := 0; i < count; i++ {
		var length int32
		if err := binary.Read(dataReader, binary.LittleEndian, &length); err != nil {
			return nil, fmt.Errorf("error reading message length: %v", err)
		}
		msg := make([]byte, length)
		if _, err := dataReader.Read(msg); err != nil {
			return nil, fmt.Errorf("error reading message: %v", err)
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

// calculateTotalEncodedSize calculates the total size of all messages to be encoded,
// including the space needed to store their lengths.
func calculateTotalEncodedSize(messages [][]byte) uint32 {
	var totalSize uint32 = 0
	// Each message length itself takes up 4 bytes (int32), plus the length of the message.
	for _, msg := range messages {
		totalSize += uint32(4)        // 4 bytes for the length of the message
		totalSize += uint32(len(msg)) // actual message size
	}
	return totalSize
}
