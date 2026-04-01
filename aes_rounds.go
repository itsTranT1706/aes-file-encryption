package main

import "fmt"

// RoundStep captures the AES state matrix at a specific step
type RoundStep struct {
	Label  string     `json:"label"`
	Matrix [][]string `json:"matrix"`
}

func stateToMatrix(state [][]byte) [][]string {
	matrix := make([][]string, 4)
	for i := 0; i < 4; i++ {
		matrix[i] = make([]string, 4)
		for j := 0; j < 4; j++ {
			matrix[i][j] = fmt.Sprintf("%02x", state[i][j])
		}
	}
	return matrix
}

func buildState(block []byte) [][]byte {
	padded := make([]byte, 16)
	copy(padded, block)
	state := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		state[i] = make([]byte, 4)
		for j := 0; j < 4; j++ {
			state[i][j] = padded[i+4*j]
		}
	}
	return state
}

func cloneState(state [][]byte) [][]byte {
	cp := make([][]byte, 4)
	for i := range state {
		cp[i] = make([]byte, 4)
		copy(cp[i], state[i])
	}
	return cp
}

func stateToBytes(state [][]byte) []byte {
	res := make([]byte, 16)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			res[i+4*j] = state[i][j]
		}
	}
	return res
}

func snap(state [][]byte, label string) RoundStep {
	return RoundStep{label, stateToMatrix(cloneState(state))}
}

// EncryptWithRounds returns ciphertext + per-step state snapshots
func (a *AES) EncryptWithRounds(block []byte) ([]byte, []RoundStep) {
	var steps []RoundStep
	state := buildState(block)
	steps = append(steps, snap(state, "Initial State"))

	a.addRoundKey(state, 0)
	steps = append(steps, snap(state, "Round 0: AddRoundKey"))

	for r := 1; r < a.Nr; r++ {
		a.subBytes(state)
		steps = append(steps, snap(state, fmt.Sprintf("Round %d: SubBytes", r)))
		a.shiftRows(state)
		steps = append(steps, snap(state, fmt.Sprintf("Round %d: ShiftRows", r)))
		a.mixColumns(state)
		steps = append(steps, snap(state, fmt.Sprintf("Round %d: MixColumns", r)))
		a.addRoundKey(state, r)
		steps = append(steps, snap(state, fmt.Sprintf("Round %d: AddRoundKey", r)))
	}

	a.subBytes(state)
	steps = append(steps, snap(state, fmt.Sprintf("Round %d: SubBytes", a.Nr)))
	a.shiftRows(state)
	steps = append(steps, snap(state, fmt.Sprintf("Round %d: ShiftRows", a.Nr)))
	a.addRoundKey(state, a.Nr)
	steps = append(steps, snap(state, fmt.Sprintf("Round %d: AddRoundKey → Result ✓", a.Nr)))

	return stateToBytes(state), steps
}

// DecryptWithRounds returns plaintext + per-step state snapshots
func (a *AES) DecryptWithRounds(block []byte) ([]byte, []RoundStep) {
	var steps []RoundStep
	state := buildState(block)
	steps = append(steps, snap(state, "Initial State (Ciphertext)"))

	a.addRoundKey(state, a.Nr)
	steps = append(steps, snap(state, fmt.Sprintf("Round 0: AddRoundKey (Key %d)", a.Nr)))

	for r := a.Nr - 1; r >= 1; r-- {
		dr := a.Nr - r
		a.invShiftRows(state)
		steps = append(steps, snap(state, fmt.Sprintf("Round %d: InvShiftRows", dr)))
		a.invSubBytes(state)
		steps = append(steps, snap(state, fmt.Sprintf("Round %d: InvSubBytes", dr)))
		a.addRoundKey(state, r)
		steps = append(steps, snap(state, fmt.Sprintf("Round %d: AddRoundKey (Key %d)", dr, r)))
		a.invMixColumns(state)
		steps = append(steps, snap(state, fmt.Sprintf("Round %d: InvMixColumns", dr)))
	}

	a.invShiftRows(state)
	steps = append(steps, snap(state, fmt.Sprintf("Round %d: InvShiftRows", a.Nr)))
	a.invSubBytes(state)
	steps = append(steps, snap(state, fmt.Sprintf("Round %d: InvSubBytes", a.Nr)))
	a.addRoundKey(state, 0)
	steps = append(steps, snap(state, fmt.Sprintf("Round %d: AddRoundKey → Result ✓", a.Nr)))

	return stateToBytes(state), steps
}
