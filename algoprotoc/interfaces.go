package algoprotoc

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

type CipherMode int

const (
	ModeECB CipherMode = iota
	ModeCBC
	ModePCBC
	ModeCFB
	ModeOFB
	ModeCTR
	ModeRandomDelta
)

type PaddingMode int

const (
	PaddingZeros PaddingMode = iota
	PaddingANSIX923
	PaddingPKCS7
	PaddingISO10126
)

type KeyExpander interface {
	ExpandKey(key []byte) ([][]byte, error)
}

type CipherTransformation interface {
	EncryptBlock(inputBlock []byte, roundKey []byte) ([]byte, error)
	DecryptBlock(inputBlock []byte, roundKey []byte) ([]byte, error)
}

type SymmetricCipher interface {
	SetKey(key []byte) error
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

type CryptoContext struct {
	key         []byte
	cipher      SymmetricCipher
	blockSize   int
	mode        CipherMode
	padding     PaddingMode
	iv          []byte
	extraParams map[string]interface{}
}

func NewCryptoContext(
	key []byte,
	cipher SymmetricCipher,
	mode CipherMode,
	padding PaddingMode,
	iv []byte,
	blockSize int,
	extraParams ...interface{}) (*CryptoContext, error) {

	if len(key) != blockSize && len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key size is invalid")
	}

	ctx := &CryptoContext{
		key:         key,
		cipher:      cipher,
		mode:        mode,
		padding:     padding,
		iv:          iv,
		blockSize:   blockSize,
		extraParams: make(map[string]interface{}),
	}

	if err := ctx.cipher.SetKey(key); err != nil {
		return nil, fmt.Errorf("failed to set key: %w", err)
	}

	for i := 0; i < len(extraParams); i += 2 {
		if i+1 < len(extraParams) {
			paramKey, ok := extraParams[i].(string)
			if ok {
				ctx.extraParams[paramKey] = extraParams[i+1]
			}
		}
	}

	err := ctx.SetKey(key)
	if err != nil {
		return nil, err
	}

	return ctx, nil
}

func (ctx *CryptoContext) SetKey(key []byte) error {
	if ctx.cipher == nil {
		return errors.New("cipher not initialized")
	}
	return ctx.cipher.SetKey(key)
}

func (ctx *CryptoContext) applyPadding(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize
	paddingNeeded := blockSize - (len(data) % blockSize)
	if paddingNeeded == 0 {
		paddingNeeded = blockSize
	}

	switch ctx.padding {
	case PaddingZeros:
		return applyZerosPadding(data, paddingNeeded), nil
	case PaddingANSIX923:
		return applyANSIX923Padding(data, paddingNeeded), nil
	case PaddingPKCS7:
		return applyPKCS7Padding(data, paddingNeeded), nil
	case PaddingISO10126:
		return applyISO10126Padding(data, paddingNeeded)
	default:
		return nil, errors.New("неподдерживаемый режим набивки")
	}
}

func (ctx *CryptoContext) removePadding(data []byte) ([]byte, error) {
	switch ctx.padding {
	case PaddingZeros:
		return removeZerosPadding(data), nil
	case PaddingANSIX923:
		return removeANSIX923Padding(data)
	case PaddingPKCS7:
		return removePKCS7Padding(data)
	case PaddingISO10126:
		return removeANSIX923Padding(data)
	default:
		return nil, errors.New("неподдерживаемый режим набивки")
	}
}

func applyZerosPadding(data []byte, paddingNeeded int) []byte {
	padding := bytes.Repeat([]byte{0}, paddingNeeded)
	return append(data, padding...)
}

func removeZerosPadding(data []byte) []byte {
	return bytes.TrimRight(data, "\x00")
}

func applyANSIX923Padding(data []byte, paddingNeeded int) []byte {
	padding := append(bytes.Repeat([]byte{0}, paddingNeeded-1), byte(paddingNeeded))
	return append(data, padding...)
}

func removeANSIX923Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("данные пусты")
	}
	paddingLength := int(data[len(data)-1])
	if paddingLength > len(data) {
		return nil, errors.New("неверная длина набивки")
	}
	return data[:len(data)-paddingLength], nil
}

func applyPKCS7Padding(data []byte, paddingNeeded int) []byte {
	padding := bytes.Repeat([]byte{byte(paddingNeeded)}, paddingNeeded)
	return append(data, padding...)
}

func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("данные пусты")
	}
	paddingLength := int(data[len(data)-1])
	if paddingLength > len(data) || paddingLength == 0 {
		return nil, errors.New("неверная длина набивки")
	}
	for i := 1; i <= paddingLength; i++ {
		if data[len(data)-i] != byte(paddingLength) {
			return nil, errors.New("неверные данные набивки")
		}
	}
	return data[:len(data)-paddingLength], nil
}

func applyISO10126Padding(data []byte, paddingNeeded int) ([]byte, error) {

	padding := make([]byte, paddingNeeded)
	_, err := rand.Read(padding[:paddingNeeded-1])
	if err != nil {
		return nil, err
	}
	padding[paddingNeeded-1] = byte(paddingNeeded)
	return append(data, padding...), nil
}

func (ctx *CryptoContext) Encrypt(data []byte) ([]byte, error) {
	dataWithPadding, err := ctx.applyPadding(data)
	if err != nil {
		return nil, err
	}

	var encryptedData []byte

	switch ctx.mode {
	case ModeECB:
		encryptedData, err = ctx.encryptECB(dataWithPadding)
	case ModeCBC:
		encryptedData, err = ctx.encryptCBC(dataWithPadding)
	case ModePCBC:
		encryptedData, err = ctx.encryptPCBC(dataWithPadding)
	case ModeCFB:
		encryptedData, err = ctx.encryptCFB(dataWithPadding)
	case ModeOFB:
		encryptedData, err = ctx.encryptOFB(dataWithPadding)
	case ModeCTR:
		encryptedData, err = ctx.encryptCTR(dataWithPadding)
	case ModeRandomDelta:
		encryptedData, err = ctx.encryptRandomDelta(dataWithPadding)
	default:
		return nil, errors.New("неподдерживаемый режим шифрования")
	}
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}
	return encryptedData, nil
}

func (ctx *CryptoContext) Decrypt(data []byte) ([]byte, error) {
	var decryptedData []byte
	var err error

	switch ctx.mode {
	case ModeECB:
		decryptedData, err = ctx.decryptECB(data)
	case ModeCBC:
		decryptedData, err = ctx.decryptCBC(data)
	case ModePCBC:
		decryptedData, err = ctx.decryptPCBC(data)
	case ModeCFB:
		decryptedData, err = ctx.decryptCFB(data)
	case ModeOFB:
		decryptedData, err = ctx.decryptOFB(data)
	case ModeCTR:
		decryptedData, err = ctx.decryptCTR(data)
	case ModeRandomDelta:
		decryptedData, err = ctx.decryptRandomDelta(data)
	default:
		return nil, errors.New("неподдерживаемый режим шифрования")
	}

	if err != nil {
		return nil, err
	}

	decryptedData, err = ctx.removePadding(decryptedData)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func (ctx *CryptoContext) EncryptAsync(data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errorChan)

		encrypted, err := ctx.Encrypt(data)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- encrypted
	}()

	return resultChan, errorChan
}

func (cstc *CryptoContext) DecryptAsync(data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errorChan)

		decrypted, err := cstc.Decrypt(data)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- decrypted
	}()

	return resultChan, errorChan
}

func (cstc *CryptoContext) EncryptToFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	data, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	encryptedData, err := cstc.Encrypt(data)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	if _, err := outputFile.Write(encryptedData); err != nil {
		return fmt.Errorf("failed to write to output file: %v", err)
	}

	return nil
}
func (cstc *CryptoContext) DecryptFromFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	data, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	decryptedData, err := cstc.Decrypt(data)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}

	if _, err := outputFile.Write(decryptedData); err != nil {
		return fmt.Errorf("failed to write to output file: %v", err)
	}

	return nil
}

func (ctx *CryptoContext) encryptECB(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize
	if len(data)%blockSize != 0 {
		return nil, errors.New("данные не кратны размеру блока")
	}

	numBlocks := len(data) / blockSize
	result := make([]byte, len(data))

	var wg sync.WaitGroup
	ch := make(chan error, numBlocks)
	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			bs := start * blockSize
			block := data[bs : bs+blockSize]

			var err error

			encryptedBlock, err := ctx.cipher.Encrypt(block)
			if err != nil {
				ch <- fmt.Errorf("encryption failed at block %d: %w", start, err)
				return
			}
			copy(result[bs:], encryptedBlock)
		}(i)
	}

	wg.Wait()
	close(ch)

	if err, ok := <-ch; ok {
		return nil, err
	}

	return result, nil
}

func (ctx *CryptoContext) decryptECB(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize
	if len(data)%blockSize != 0 {
		return nil, errors.New("данные не кратны размеру блока")
	}

	numBlocks := len(data) / blockSize
	result := make([]byte, len(data))

	var wg sync.WaitGroup
	ch := make(chan error)
	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			bs := start * blockSize
			block := data[bs : bs+blockSize]

			decryptedBlock, err := ctx.cipher.Decrypt(block)
			if err != nil {
				ch <- fmt.Errorf("decryption failed at block %d: %w", start, err)
				return
			}
			copy(result[bs:], decryptedBlock)
		}(i)
	}

	wg.Wait()
	close(ch)

	if err, ok := <-ch; ok {
		return nil, err
	}

	return result, nil
}

func (ctx *CryptoContext) encryptCBC(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize
	if len(data)%blockSize != 0 {
		return nil, errors.New("данные не кратны размеру блока")
	}

	if ctx.iv == nil || len(ctx.iv) != blockSize {
		return nil, errors.New("неверный вектор инициализации (IV)")
	}

	result := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, ctx.iv)

	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		block := data[start : start+blockSize]

		inputBlock := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			inputBlock[j] = block[j] ^ prevBlock[j]
		}

		encryptedBlock, err := ctx.cipher.Encrypt(inputBlock)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at block %d: %w", i, err)
		}

		copy(result[start:], encryptedBlock)
		copy(prevBlock, encryptedBlock)
	}

	return result, nil
}

func (ctx *CryptoContext) decryptCBC(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize
	if len(data)%blockSize != 0 {
		return nil, errors.New("данные не кратны размеру блока")
	}

	if ctx.iv == nil || len(ctx.iv) != blockSize {
		return nil, errors.New("неверный вектор инициализации (IV)")
	}

	result := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, ctx.iv)

	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		block := data[start : start+blockSize]

		decryptedBlock, err := ctx.cipher.Decrypt(block)
		if err != nil {
			return nil, err
		}

		for j := 0; j < blockSize; j++ {
			result[start+j] = decryptedBlock[j] ^ prevBlock[j]
		}

		copy(prevBlock, block)
	}

	return result, nil
}

func (ctx *CryptoContext) encryptPCBC(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize
	if len(data)%blockSize != 0 {
		return nil, errors.New("данные не кратны размеру блока")
	}

	if ctx.iv == nil || len(ctx.iv) != blockSize {
		return nil, errors.New("неверный вектор инициализации (IV)")
	}

	result := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	prevPlainBlock := make([]byte, blockSize)
	prevCipherBlock := make([]byte, blockSize)
	copy(prevCipherBlock, ctx.iv)

	for i := 0; i < numBlocks; i++ {
		bs := i * blockSize
		plaintextBlock := data[bs : bs+blockSize]

		inputBlock := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			inputBlock[j] = plaintextBlock[j] ^ prevPlainBlock[j] ^ prevCipherBlock[j]
		}

		encryptedBlock, err := ctx.cipher.Encrypt(inputBlock)
		if err != nil {
			return nil, err
		}

		copy(result[bs:], encryptedBlock)
		copy(prevPlainBlock, plaintextBlock)
		copy(prevCipherBlock, encryptedBlock)
	}

	return result, nil
}

func (ctx *CryptoContext) decryptPCBC(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize
	if len(data)%blockSize != 0 {
		return nil, errors.New("данные не кратны размеру блока")
	}

	if ctx.iv == nil || len(ctx.iv) != blockSize {
		return nil, errors.New("неверный вектор инициализации (IV)")
	}

	result := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	prevPlainBlock := make([]byte, blockSize)
	prevCipherBlock := make([]byte, blockSize)
	copy(prevCipherBlock, ctx.iv)

	for i := 0; i < numBlocks; i++ {
		bs := i * blockSize
		plaintextBlock := data[bs : bs+blockSize]

		decryptedBlock, err := ctx.cipher.Decrypt(plaintextBlock)
		if err != nil {
			return nil, fmt.Errorf("decryption failed at block %d: %w", i, err)
		}

		for j := 0; j < blockSize; j++ {
			result[bs+j] = decryptedBlock[j] ^ prevPlainBlock[j] ^ prevCipherBlock[j]
		}

		copy(prevPlainBlock, result[bs:bs+blockSize])
		copy(prevCipherBlock, plaintextBlock)
	}

	return result, nil
}

func (ctx *CryptoContext) encryptCFB(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize

	if ctx.iv == nil || len(ctx.iv) != blockSize {
		return nil, errors.New("неверный вектор инициализации (IV)")
	}

	result := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	feedback := make([]byte, blockSize)
	copy(feedback, ctx.iv)

	for i := 0; i < numBlocks; i++ {
		bs := i * blockSize
		plaintextBlock := data[bs : bs+blockSize]

		outputBlock, err := ctx.cipher.Encrypt(feedback)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at block %d: %w", i, err)
		}

		for j := 0; j < blockSize; j++ {
			result[bs+j] = plaintextBlock[j] ^ outputBlock[j]
		}

		copy(feedback, result[bs:bs+blockSize])
	}

	return result, nil
}

func (ctx *CryptoContext) decryptCFB(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize

	if ctx.iv == nil || len(ctx.iv) != blockSize {
		return nil, errors.New("неверный вектор инициализации (IV)")
	}

	result := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	feedback := make([]byte, blockSize)
	copy(feedback, ctx.iv)

	for i := 0; i < numBlocks; i++ {
		bs := i * blockSize
		ciphertextBlock := data[bs : bs+blockSize]

		outputBlock, err := ctx.cipher.Encrypt(feedback)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at block %d: %w", i, err)
		}

		for j := 0; j < blockSize; j++ {
			result[bs+j] = ciphertextBlock[j] ^ outputBlock[j]
		}

		copy(feedback, ciphertextBlock)
	}

	return result, nil
}

func (ctx *CryptoContext) encryptOFB(data []byte) ([]byte, error) {
	return ctx.processOFB(data)
}

func (ctx *CryptoContext) decryptOFB(data []byte) ([]byte, error) {
	return ctx.processOFB(data)
}

func (ctx *CryptoContext) processOFB(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize

	if ctx.iv == nil || len(ctx.iv) != blockSize {
		return nil, errors.New("неверный вектор инициализации (IV)")
	}

	result := make([]byte, len(data))
	feedback := make([]byte, blockSize)
	copy(feedback, ctx.iv)
	fmt.Printf("Используемый IV: %x\n", ctx.iv)

	for i := 0; i < len(data); i += blockSize {
		outputBlock, err := ctx.cipher.Encrypt(feedback)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at block %d: %w", i/blockSize, err)
		}

		for j := 0; j < blockSize && i+j < len(data); j++ {
			result[i+j] = data[i+j] ^ outputBlock[j]
		}

		copy(feedback, outputBlock)
	}

	return result, nil
}

func (ctx *CryptoContext) encryptCTR(data []byte) ([]byte, error) {
	return ctx.processCTR(data)
}

func (ctx *CryptoContext) decryptCTR(data []byte) ([]byte, error) {
	return ctx.processCTR(data)
}

func (ctx *CryptoContext) processCTR(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize

	if ctx.iv == nil || len(ctx.iv) != blockSize {
		return nil, errors.New("неверный вектор инициализации (IV)")
	}

	numBlocks := (len(data) + blockSize - 1) / blockSize
	result := make([]byte, len(data))
	counter := make([]byte, blockSize)
	copy(counter, ctx.iv)

	var wg sync.WaitGroup
	ch := make(chan error, numBlocks)
	mutex := &sync.Mutex{}

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(blockIndex int) {
			defer wg.Done()

			mutex.Lock()
			currentCounter := make([]byte, blockSize)
			copy(currentCounter, counter)
			incrementCounter(currentCounter, blockIndex)
			mutex.Unlock()

			keystreamBlock, err := ctx.cipher.Encrypt(currentCounter)
			if err != nil {
				ch <- fmt.Errorf("encryption failed at block %d: %w", blockIndex, err)
				return
			}

			bs := blockIndex * blockSize
			be := bs + blockSize
			if be > len(data) {
				be = len(data)
			}

			chunkSize := be - bs
			for j := 0; j < chunkSize; j++ {
				result[bs+j] = data[bs+j] ^ keystreamBlock[j]
			}
		}(i)
	}

	wg.Wait()
	close(ch)

	if err, ok := <-ch; ok {
		return nil, err
	}
	return result, nil
}

func (ctx *CryptoContext) encryptRandomDelta(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize

	result := make([]byte, len(data))

	delta := make([]byte, blockSize)

	for i := 0; i < len(data); i += blockSize {
		blockEnd := i + blockSize
		if blockEnd > len(data) {
			blockEnd = len(data)
		}

		block := data[i:blockEnd]
		for j := 0; j < len(block); j++ {
			result[i+j] = block[j] + delta[j%blockSize]
		}
	}

	return append(delta, result...), nil
}

func (ctx *CryptoContext) decryptRandomDelta(data []byte) ([]byte, error) {
	blockSize := ctx.blockSize

	if len(data) < blockSize {
		return nil, errors.New("data too short to contain delta")
	}
	delta := data[:blockSize]
	data = data[blockSize:]

	decrypted := make([]byte, len(data))

	for i := 0; i < len(data); i += blockSize {
		blockEnd := i + blockSize
		if blockEnd > len(data) {
			blockEnd = len(data)
		}

		block := data[i:blockEnd]
		for j := 0; j < len(block); j++ {
			decrypted[i+j] = block[j] - delta[j%blockSize]
		}
	}

	return decrypted, nil
}

func incrementCounter(counter []byte, blockIndex int) {
	carry := blockIndex
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		sum := int(counter[i]) + (carry & 0xFF)
		counter[i] = byte(sum & 0xFF)
		carry = (carry >> 8) + (sum >> 8)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (ctx *CryptoContext) EncryptFileAsync(inputPath, outputPath string) <-chan error {
	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		err := ctx.encryptFile(inputPath, outputPath)
		if err != nil {
			errChan <- err
		}
	}()
	return errChan
}

func (ctx *CryptoContext) encryptFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	blockSize := ctx.blockSize
	bufferSize := blockSize * 1024
	buffer := make([]byte, bufferSize)
	pendingData := make([]byte, 0)

	for {
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		pendingData = append(pendingData, buffer[:n]...)

		for len(pendingData) >= blockSize {
			block := pendingData[:blockSize]
			encryptedBlock, err := ctx.cipher.Encrypt(block)
			if err != nil {
				return fmt.Errorf("encryption failed: %v", err)
			}
			if _, err := outputFile.Write(encryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
			pendingData = pendingData[blockSize:]
		}

		if err == io.EOF {
			break
		}
	}

	if len(pendingData) > 0 {
		paddedData, err := ctx.applyPadding(pendingData)
		if err != nil {
			return fmt.Errorf("failed to add padding: %v", err)
		}
		for len(paddedData) >= blockSize {
			block := paddedData[:blockSize]
			encryptedBlock, err := ctx.cipher.Encrypt(block)
			if err != nil {
				return fmt.Errorf("encryption failed: %v", err)
			}
			if _, err := outputFile.Write(encryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
			paddedData = paddedData[blockSize:]
		}
	} else {
		paddedData, err := ctx.applyPadding(nil)
		if err != nil {
			return fmt.Errorf("failed to add padding: %v", err)
		}
		if len(paddedData) > 0 {
			encryptedBlock, err := ctx.cipher.Encrypt(paddedData)
			if err != nil {
				return fmt.Errorf("encryption failed: %v", err)
			}
			if _, err := outputFile.Write(encryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
		}
	}

	return nil
}

func (ctx *CryptoContext) DecryptFileAsync(inputPath, outputPath string) <-chan error {
	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		err := ctx.decryptFile(inputPath, outputPath)
		if err != nil {
			errChan <- err
		}
	}()
	return errChan
}

func (ctx *CryptoContext) decryptFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	blockSize := ctx.blockSize
	bufferSize := blockSize * 1024
	buffer := make([]byte, bufferSize)
	pendingData := make([]byte, 0)

	for {
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		pendingData = append(pendingData, buffer[:n]...)
		for len(pendingData) >= blockSize*2 {
			block := pendingData[:blockSize]
			decryptedBlock, err := ctx.cipher.Decrypt(block)
			if err != nil {
				return fmt.Errorf("decryption failed: %v", err)
			}
			if _, err := outputFile.Write(decryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
			pendingData = pendingData[blockSize:]
		}

		if err == io.EOF {
			break
		}
	}

	if len(pendingData) > 0 {
		if len(pendingData)%blockSize != 0 {
			return fmt.Errorf("encrypted data is not a multiple of block size")
		}

		for len(pendingData) > 0 {
			block := pendingData[:blockSize]
			decryptedBlock, err := ctx.cipher.Decrypt(block)
			if err != nil {
				return fmt.Errorf("decryption failed: %v", err)
			}
			pendingData = pendingData[blockSize:]

			if len(pendingData) == 0 {
				decryptedBlock, err = ctx.removePadding(decryptedBlock)
				if err != nil {
					return fmt.Errorf("failed to remove padding: %v", err)
				}
			}

			if _, err := outputFile.Write(decryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
		}
	}

	return nil
}
