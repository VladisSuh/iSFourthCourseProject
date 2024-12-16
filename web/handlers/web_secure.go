package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
	"sync"

	"github.com/joho/godotenv"
	"iSFourthCourseProject/algoprotoc"
)

var secretKey []byte

func init() {
	errs := godotenv.Load()
	if errs != nil {
		log.Println("Файл .env не найден, продолжаем без него")
	}
	keyHex := os.Getenv("SECRET_KEY")
	if keyHex == "" {
		panic("SECRET_KEY не установлена в переменных окружения")
	}
	var err error
	secretKey, err = hex.DecodeString(keyHex)
	if err != nil {
		panic("Ошибка декодирования SECRET_KEY: " + err.Error())
	}
	if len(secretKey) != 32 {
		panic("SECRET_KEY должна быть 32 байта (64 символа в hex)")
	}
}

func EncryptPrivateKey(privateKey []byte) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, privateKey, nil)
	return hex.EncodeToString(ciphertext), nil
}

func DecryptPrivateKey(encryptedPrivateKeyHex string) ([]byte, error) {
	encryptedPrivateKey, err := hex.DecodeString(encryptedPrivateKeyHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedPrivateKey) < nonceSize {
		return nil, errors.New("зашифрованный ключ слишком короткий")
	}

	nonce, ciphertext := encryptedPrivateKey[:nonceSize], encryptedPrivateKey[nonceSize:]
	privateKey, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

var cipherContexts = struct {
	m map[string]*algoprotoc.CryptoContext
	sync.RWMutex
}{
	m: make(map[string]*algoprotoc.CryptoContext),
}

// SaveCipherContext сохраняет контекст шифрования для конкретной комнаты и пользователя
func SaveCipherContext(roomID, username string, ctx *algoprotoc.CryptoContext) {
	key := roomID + "_" + username
	cipherContexts.Lock()
	defer cipherContexts.Unlock()
	cipherContexts.m[key] = ctx
}

// LoadCipherContext загружает контекст шифрования для конкретной комнаты и пользователя
func LoadCipherContext(roomID, username string) *algoprotoc.CryptoContext {
	key := roomID + "_" + username
	cipherContexts.RLock()
	defer cipherContexts.RUnlock()
	return cipherContexts.m[key]
}

// InitCipher инициализирует cipherContext с заданными параметрами на основе hashedSharedKey
func InitCipher(hashedSharedKey []byte, algorithmName, mode, padding string) *algoprotoc.CryptoContext {
	hashedKey := sha256.Sum256(hashedSharedKey)
	finalKey := hashedKey[:16]

	var symmetricAlgorithm algoprotoc.SymmetricCipher
	if algorithmName == "macguffin" {
		symmetricAlgorithm = &algoprotoc.MacGuffinCipher{}
	} else if algorithmName == "rc5" {
		symmetricAlgorithm = algoprotoc.NewRC5()
	} else {
		log.Fatalf("Неизвестный алгоритм: %s", algorithmName)
	}

	err := symmetricAlgorithm.SetKey(finalKey)
	if err != nil {
		log.Fatalf("Ошибка при установке ключа: %v", err)
	}

	cipherMode := algoprotoc.ModeCBC
	switch mode {
	case "ECB":
		cipherMode = algoprotoc.ModeECB
	case "CBC":
		cipherMode = algoprotoc.ModeCBC
	case "CFB":
		cipherMode = algoprotoc.ModeCFB
	case "OFB":
		cipherMode = algoprotoc.ModeOFB
	case "CTR":
		cipherMode = algoprotoc.ModeCTR
	case "RandomDelta":
		cipherMode = algoprotoc.ModeRandomDelta
	default:
		log.Fatalf("Неизвестный режим шифрования: %s", mode)
	}

	paddingMode := algoprotoc.PaddingPKCS7
	switch padding {
	case "Zeros":
		paddingMode = algoprotoc.PaddingZeros
	case "ANSIX923":
		paddingMode = algoprotoc.PaddingANSIX923
	case "PKCS7":
		paddingMode = algoprotoc.PaddingPKCS7
	case "ISO10126":
		paddingMode = algoprotoc.PaddingISO10126
	default:
		log.Fatalf("Неизвестный режим набивки: %s", padding)
	}

	ivHash := sha256.Sum256(hashedSharedKey)
	iv := ivHash[:16]

	cipherContext, err := algoprotoc.NewCryptoContext(
		finalKey,
		symmetricAlgorithm,
		cipherMode,
		paddingMode,
		iv,
		16,
	)
	if err != nil {
		log.Fatalf("Ошибка при инициализации контекста шифрования: %v", err)
	}

	return cipherContext
}
