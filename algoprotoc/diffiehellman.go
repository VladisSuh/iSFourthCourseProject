package algoprotoc

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// Генерирует большое простое число
func GeneratePrime(bits int) (*big.Int, error) {
	prime, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return prime, nil
}

// Генерирует приватный ключ (случайное число меньше prime)
func GeneratePrivateKey(prime *big.Int) (*big.Int, error) {
	privateKey, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Публичный ключ g^privateKey mod p
func GeneratePublicKey(g, privateKey, prime *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(g, privateKey, prime)
	return publicKey
}

// Общий ключ (otherPublicKey ^ privateKey) mod p
func GenerateSharedKey(privateKey, otherPublicKey, prime *big.Int) *big.Int {
	sharedKey := new(big.Int).Exp(otherPublicKey, privateKey, prime)
	return sharedKey
}

// Хеширует общий ключ с помощью SHA-256
func HashSharedKey(sharedKey *big.Int) []byte {
	hash := sha256.New()
	hash.Write(sharedKey.Bytes())
	hashedKey := hash.Sum(nil)
	return hashedKey
}
