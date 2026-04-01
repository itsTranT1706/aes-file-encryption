package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type EncryptAPIReq struct {
	Text string `json:"text"`
	Key  string `json:"key"`
}

type DecryptAPIReq struct {
	CiphertextHex string `json:"ciphertextHex"`
	IVHex         string `json:"ivHex"`
	Key           string `json:"key"`
}

type APIResp struct {
	Success    bool        `json:"success"`
	Error      string      `json:"error,omitempty"`
	ResultHex  string      `json:"resultHex,omitempty"`
	ResultText string      `json:"resultText,omitempty"`
	IV         string      `json:"iv,omitempty"`
	Steps      []RoundStep `json:"steps,omitempty"`
	TimeNs     int64       `json:"timeNs"`
	TimeLabel  string      `json:"timeLabel"`
	Iter       int         `json:"iter"`
	InputSize  int         `json:"inputSize"`
	OutputSize int         `json:"outputSize"`
}

// benchmarkTime runs fn N times and returns average duration in nanoseconds.
// If a single run is >= 1µs we skip benchmarking to keep response fast.
func benchmarkTime(fn func()) (avgNs int64, iterations int) {
	// Quick single run first
	start := time.Now()
	fn()
	single := time.Since(start).Nanoseconds()

	if single >= 1000 {
		// Already measurable – return as-is
		return single, 1
	}
	// Too fast for a single tick – run 10 000 iterations
	const N = 10_000
	start = time.Now()
	for i := 0; i < N; i++ {
		fn()
	}
	total := time.Since(start).Nanoseconds()
	return total / N, N
}

func fmtNs(ns int64) string {
	switch {
	case ns == 0:
		return "< 1 ns"
	case ns < 1_000:
		return fmt.Sprintf("%d ns", ns)
	case ns < 1_000_000:
		return fmt.Sprintf("%.2f µs", float64(ns)/1_000)
	default:
		return fmt.Sprintf("%.3f ms", float64(ns)/1_000_000)
	}
}

func startServer(port string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/encrypt", handleEncrypt)
	mux.HandleFunc("/api/decrypt", handleDecrypt)
	mux.HandleFunc("/api/encrypt-file", handleEncryptFile)
	mux.HandleFunc("/api/decrypt-file", handleDecryptFile)
	mux.HandleFunc("/api/nist", handleNIST)

	addr := fmt.Sprintf(":%s", port)
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║      🔐 AES Visualizer v1.2         ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Printf("   🌐  http://localhost%s\n\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func setHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, X-AES-Time-Label, X-AES-Time-Ns, X-AES-Iter, X-AES-Input-Size, X-AES-Output-Size, X-AES-IV, X-AES-Cipher-Preview")
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	setHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}
	var req EncryptAPIReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, APIResp{Success: false, Error: "Invalid JSON"})
		return
	}
	key := []byte(req.Key)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		writeJSON(w, APIResp{Success: false, Error: fmt.Sprintf("Key phải là 16, 24 hoặc 32 ký tự (hiện tại: %d)", len(key))})
		return
	}
	if len(req.Text) == 0 {
		writeJSON(w, APIResp{Success: false, Error: "Plaintext không được rỗng"})
		return
	}

	plaintext := []byte(req.Text)
	aesInst := NewAES(key, false)
	iv, _ := GenerateRandomIV()

	// Build first block XOR'd with IV for visualization
	padded := pkcs7Pad(plaintext, 16)
	xorBlock := make([]byte, 16)
	for i := 0; i < 16; i++ {
		xorBlock[i] = padded[i] ^ iv[i]
	}
	_, steps := aesInst.EncryptWithRounds(xorBlock)

	// Actual encrypt (for result)
	encrypted, err := CBCEncrypt(aesInst, plaintext, iv)
	if err != nil {
		writeJSON(w, APIResp{Success: false, Error: err.Error()})
		return
	}

	// Benchmark for accurate timing
	avgNs, iters := benchmarkTime(func() {
		CBCEncrypt(NewAES(key, false), plaintext, iv)
	})

	writeJSON(w, APIResp{
		Success:    true,
		ResultHex:  hex.EncodeToString(encrypted[16:]),
		IV:         hex.EncodeToString(iv),
		Steps:      steps,
		TimeNs:     avgNs,
		TimeLabel:  fmtNs(avgNs),
		Iter:       iters,
		InputSize:  len(plaintext),
		OutputSize: len(encrypted),
	})
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}
	var req DecryptAPIReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, APIResp{Success: false, Error: "Invalid JSON"})
		return
	}
	key := []byte(req.Key)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		writeJSON(w, APIResp{Success: false, Error: fmt.Sprintf("Key phải là 16, 24 hoặc 32 ký tự (hiện tại: %d)", len(key))})
		return
	}
	ivBytes, err := hex.DecodeString(req.IVHex)
	if err != nil || len(ivBytes) != 16 {
		writeJSON(w, APIResp{Success: false, Error: "IV hex không hợp lệ (32 hex chars)"})
		return
	}
	cipherBytes, err := hex.DecodeString(req.CiphertextHex)
	if err != nil || len(cipherBytes) == 0 || len(cipherBytes)%16 != 0 {
		writeJSON(w, APIResp{Success: false, Error: "Ciphertext hex không hợp lệ"})
		return
	}

	aesInst := NewAES(key, false)
	_, steps := aesInst.DecryptWithRounds(cipherBytes[:16])

	combined := append(ivBytes, cipherBytes...)
	decrypted, err := CBCDecrypt(aesInst, combined)
	if err != nil {
		writeJSON(w, APIResp{Success: false, Error: "Decryption failed: " + err.Error()})
		return
	}

	// Benchmark for accurate timing
	avgNs, iters := benchmarkTime(func() {
		CBCDecrypt(NewAES(key, false), combined)
	})

	writeJSON(w, APIResp{
		Success:    true,
		ResultHex:  hex.EncodeToString(decrypted),
		ResultText: string(decrypted),
		Steps:      steps,
		TimeNs:     avgNs,
		TimeLabel:  fmtNs(avgNs),
		Iter:       iters,
		InputSize:  len(cipherBytes),
		OutputSize: len(decrypted),
	})
}

func handleNIST(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	keyHex := "000102030405060708090a0b0c0d0e0f"
	plaintextHex := "00112233445566778899aabbccddeeff"
	expectedHex := "69c4e0d86a7b0430d8cdb78070b4c55a"

	key, _ := hex.DecodeString(keyHex)
	plaintext, _ := hex.DecodeString(plaintextHex)

	aesInst := NewAES(key, false)
	ciphertext, steps := aesInst.EncryptWithRounds(plaintext)
	resultHex := hex.EncodeToString(ciphertext)

	writeJSON(w, map[string]interface{}{
		"success":      true,
		"passed":       resultHex == expectedHex,
		"keyHex":       keyHex,
		"plaintextHex": plaintextHex,
		"resultHex":    resultHex,
		"expectedHex":  expectedHex,
		"steps":        steps,
	})
}

func handleEncryptFile(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		setHeaders(w)
		return
	}
	err := r.ParseMultipartForm(10 << 20) // 10MB limit
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	keyStr := r.FormValue("key")
	key := []byte(keyStr)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		http.Error(w, "Key must be 16, 24 or 32 characters", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data := make([]byte, header.Size)
	file.Read(data)

	aesInst := NewAES(key, false)
	iv, _ := GenerateRandomIV()

	encrypted, err := CBCEncrypt(aesInst, data, iv)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	// Benchmark
	avgNs, iters := benchmarkTime(func() {
		CBCEncrypt(NewAES(key, false), data, iv)
	})

	w.Header().Set("X-AES-Time-Label", fmtNs(avgNs))
	w.Header().Set("X-AES-Time-Ns", fmt.Sprintf("%d", avgNs))
	w.Header().Set("X-AES-Iter", fmt.Sprintf("%d", iters))
	w.Header().Set("X-AES-Input-Size", fmt.Sprintf("%d", len(data)))
	w.Header().Set("X-AES-Output-Size", fmt.Sprintf("%d", len(encrypted)))
	w.Header().Set("X-AES-IV", hex.EncodeToString(iv))
	w.Header().Set("X-AES-Cipher-Preview", hex.EncodeToString(encrypted[16:]))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s.enc", header.Filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	setHeaders(w)
	w.Write(encrypted)
}

func handleDecryptFile(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		setHeaders(w)
		return
	}
	err := r.ParseMultipartForm(10 << 20) // 10MB limit
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	keyStr := r.FormValue("key")
	key := []byte(keyStr)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		http.Error(w, "Key must be 16, 24 or 32 characters", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data := make([]byte, header.Size)
	file.Read(data)

	aesInst := NewAES(key, false)
	decrypted, err := CBCDecrypt(aesInst, data)
	if err != nil {
		http.Error(w, "Decryption failed (check key or IV)", http.StatusBadRequest)
		return
	}

	// Benchmark
	avgNs, iters := benchmarkTime(func() {
		CBCDecrypt(NewAES(key, false), data)
	})

	origName := header.Filename
	if len(origName) > 4 && origName[len(origName)-4:] == ".enc" {
		origName = origName[:len(origName)-4]
	} else {
		origName = "decrypted_" + origName
	}

	w.Header().Set("X-AES-Time-Label", fmtNs(avgNs))
	w.Header().Set("X-AES-Time-Ns", fmt.Sprintf("%d", avgNs))
	w.Header().Set("X-AES-Iter", fmt.Sprintf("%d", iters))
	w.Header().Set("X-AES-Input-Size", fmt.Sprintf("%d", len(data)))
	w.Header().Set("X-AES-Output-Size", fmt.Sprintf("%d", len(decrypted)))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", origName))
	w.Header().Set("Content-Type", "application/octet-stream")
	setHeaders(w)
	w.Write(decrypted)
}
