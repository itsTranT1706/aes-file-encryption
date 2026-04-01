package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "encrypt":
		if len(os.Args) < 5 {
			fmt.Println("Usage: encrypt <input_file> <output_file> <key>")
			return
		}
		encrypt(os.Args[2], os.Args[3], os.Args[4])
	case "decrypt":
		if len(os.Args) < 5 {
			fmt.Println("Usage: decrypt <input_file> <output_file> <key>")
			return
		}
		decrypt(os.Args[2], os.Args[3], os.Args[4])
	case "test":
		runTest()
	case "debug":
		if len(os.Args) < 3 {
			fmt.Println("Usage: debug <key>")
			return
		}
		runDebug(os.Args[2])
	case "serve":
		port := "8080"
		if len(os.Args) >= 3 {
			port = os.Args[2]
		}
		startServer(port)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
	}
}

func printUsage() {
	fmt.Println("AES Scratch Implementation CLI (Supports 128, 192, 256 bits)")
	fmt.Println("Available commands:")
	fmt.Println("  encrypt <input> <output> <key>  - Encrypt a file (key: 16, 24, or 32 chars)")
	fmt.Println("  decrypt <input> <output> <key>  - Decrypt a file")
	fmt.Println("  test                            - Run NIST test vectors (AES-128)")
	fmt.Println("  debug <key>                     - Show step-by-step encryption of a sample block")
	fmt.Println("  serve [port]                    - Start web visualizer (default port: 8080)")
}

func encrypt(inputFile, outputFile, keyStr string) {
	key := []byte(keyStr)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Printf("Error: Key must be 16, 24, or 32 bytes (got %d)\n", len(key))
		return
	}

	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Error reading input file: %v\n", err)
		return
	}

	aes := NewAES(key, false)
	iv, _ := GenerateRandomIV()

	fmt.Printf("[AES-%d-CBC] Encrypting: %s -> %s\n", len(key)*8, inputFile, outputFile)
	
	start := time.Now()
	encrypted, err := CBCEncrypt(aes, data, iv)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}
	elapsed := time.Since(start)

	err = ioutil.WriteFile(outputFile, encrypted, 0644)
	if err != nil {
		fmt.Printf("Error writing output file: %v\n", err)
		return
	}

	fmt.Printf("✅ Encryption complete in %v\n", elapsed)
	fmt.Printf("Output file size: %d bytes (includes 16-byte IV)\n", len(encrypted))
}

func decrypt(inputFile, outputFile, keyStr string) {
	key := []byte(keyStr)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Printf("Error: Key must be 16, 24, or 32 bytes (got %d)\n", len(key))
		return
	}

	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Error reading input file: %v\n", err)
		return
	}

	aes := NewAES(key, false)
	
	fmt.Printf("[AES-%d-CBC] Decrypting: %s -> %s\n", len(key)*8, inputFile, outputFile)
	
	start := time.Now()
	decrypted, err := CBCDecrypt(aes, data)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		return
	}
	elapsed := time.Since(start)

	err = ioutil.WriteFile(outputFile, decrypted, 0644)
	if err != nil {
		fmt.Printf("Error writing output file: %v\n", err)
		return
	}

	fmt.Printf("✅ Decryption complete in %v\n", elapsed)
}

func runTest() {
	fmt.Println("[KIỂM THỬ CHUẨN NIST]")
	
	// NIST Test Vector for AES-128 ECB (simplest to verify core)
	keyHex := "000102030405060708090a0b0c0d0e0f"
	plaintextHex := "00112233445566778899aabbccddeeff"
	expectedHex := "69c4e0d86a7b0430d8cdb78070b4c55a"

	key, _ := hex.DecodeString(keyHex)
	plaintext, _ := hex.DecodeString(plaintextHex)
	
	aes := NewAES(key, false)
	
	fmt.Printf("- Key Round 10: ")
	for i := 40; i < 44; i++ {
		fmt.Printf("%s", hex.EncodeToString(aes.w[i]))
	}
	fmt.Println()

	ciphertext := aes.Encrypt(plaintext)
	ciphertextHex := hex.EncodeToString(ciphertext)

	fmt.Printf("- Key:       %s\n", keyHex)
	fmt.Printf("- Plaintext: %s\n", plaintextHex)
	fmt.Printf("- Kết quả:   %s\n", ciphertextHex)
	fmt.Printf("- Chuẩn:     %s\n", expectedHex)

	if ciphertextHex == expectedHex {
		fmt.Println("==> TRẠNG THÁI: KHỚP (PASS) ✓")
	} else {
		fmt.Println("==> TRẠNG THÁI: SAI (FAIL) ❌")
	}

	// Decrypt test
	decrypted := aes.Decrypt(ciphertext)
	decryptedHex := hex.EncodeToString(decrypted)
	fmt.Printf("- Decrypt:   %s\n", decryptedHex)
	if decryptedHex == plaintextHex {
		fmt.Println("==> REVERSE: KHỚP (PASS) ✓")
	} else {
		fmt.Println("==> REVERSE: SAI (FAIL) ❌")
	}
}

func runDebug(keyHex string) {
	key, _ := hex.DecodeString(keyHex)
	if len(key) != 16 {
		fmt.Printf("Error: Debug hex key must be 32 chars (16 bytes), got %d\n", len(key)*2)
		return
	}

	plaintextHex := "00112233445566778899aabbccddeeff"
	plaintext, _ := hex.DecodeString(plaintextHex)
	
	fmt.Printf("DEBUG MODE: Encrypting NIST block with key: %s\n", keyHex)
	
	aes := NewAES(key, true)
	ciphertext := aes.Encrypt(plaintext)
	
	fmt.Println("\n-------------------------------------------")
	fmt.Printf("DEBUG MODE: Decrypting resulting block\n")
	decrypted := aes.Decrypt(ciphertext)
	
	fmt.Printf("\nOriginal:   %s\n", plaintextHex)
	fmt.Printf("Result:     %s\n", hex.EncodeToString(ciphertext))
	fmt.Printf("Decrypted:  %s\n", hex.EncodeToString(decrypted))
}
