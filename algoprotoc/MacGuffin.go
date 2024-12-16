package algoprotoc

import (
	"encoding/binary"
	"errors"
)

type MacGuffinCipher struct {
	expandedKey mcgKey
}

func NewMacGuffinCipher() *MacGuffinCipher {
	return &MacGuffinCipher{}
}

func (mcg *MacGuffinCipher) SetKey(key []byte) error {
	if len(key) != 16 {
		return errors.New("MacGuffin requires a 16-byte key")
	}
	mcgKeyset(key, &mcg.expandedKey)
	return nil
}

func (mcg *MacGuffinCipher) Encrypt(data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, errors.New("data length must be a multiple of 8 bytes")
	}
	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		block := data[i : i+8]
		mcgBlockEncrypt(block, &mcg.expandedKey)
		copy(encrypted[i:], block)
	}
	return encrypted, nil
}

func (mcg *MacGuffinCipher) Decrypt(data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, errors.New("data length must be a multiple of 8 bytes")
	}
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		block := data[i : i+8]
		mcgBlockDecrypt(block, &mcg.expandedKey)
		copy(decrypted[i:], block)
	}
	return decrypted, nil
}

const (
	ROUNDS = 32
	KSIZE  = ROUNDS * 3
	TSIZE  = 1 << 16
)

type mcgKey struct {
	val [KSIZE]uint16
}

var sboxes = [8][64]uint16{
	/* 0 (s1) */
	{
		0x0002, 0x0000, 0x0000, 0x0003, 0x0003, 0x0001, 0x0001, 0x0000,
		0x0000, 0x0001, 0x0001, 0x0000, 0x0003, 0x0003, 0x0002, 0x0001,
		0x0002, 0x0002, 0x0000, 0x0000, 0x0002, 0x0002, 0x0003, 0x0001,
		0x0003, 0x0003, 0x0001, 0x0000, 0x0001, 0x0001, 0x0002, 0x0002,
		0x0000, 0x0003, 0x0001, 0x0002, 0x0002, 0x0002, 0x0002, 0x0000,
		0x0003, 0x0000, 0x0000, 0x0003, 0x0000, 0x0001, 0x0003, 0x0001,
		0x0003, 0x0001, 0x0002, 0x0003, 0x0003, 0x0001, 0x0001, 0x0002,
		0x0001, 0x0002, 0x0002, 0x0000, 0x0001, 0x0000, 0x0000, 0x0003,
	},
	/* 1 (s2) */
	{
		0x0003, 0x0001, 0x0003, 0x0002, 0x0002, 0x0000, 0x0002, 0x0001,
		0x0000, 0x0003, 0x0003, 0x0000, 0x0001, 0x0002, 0x0000, 0x0002,
		0x0003, 0x0002, 0x0001, 0x0000, 0x0000, 0x0001, 0x0003, 0x0002,
		0x0002, 0x0000, 0x0000, 0x0003, 0x0001, 0x0003, 0x0002, 0x0001,
		0x0000, 0x0003, 0x0002, 0x0002, 0x0001, 0x0002, 0x0003, 0x0001,
		0x0002, 0x0001, 0x0000, 0x0003, 0x0003, 0x0000, 0x0001, 0x0000,
		0x0001, 0x0003, 0x0002, 0x0000, 0x0002, 0x0001, 0x0000, 0x0002,
		0x0003, 0x0000, 0x0001, 0x0000, 0x0002, 0x0003, 0x0001, 0x0002,
	},
	/* 2 (s3) */
	{
		0x0002, 0x0003, 0x0000, 0x0001, 0x0003, 0x0000, 0x0002, 0x0003,
		0x0000, 0x0001, 0x0001, 0x0000, 0x0003, 0x0000, 0x0001, 0x0002,
		0x0001, 0x0000, 0x0003, 0x0002, 0x0002, 0x0001, 0x0001, 0x0002,
		0x0003, 0x0002, 0x0000, 0x0003, 0x0000, 0x0003, 0x0002, 0x0001,
		0x0003, 0x0001, 0x0000, 0x0002, 0x0000, 0x0003, 0x0003, 0x0000,
		0x0002, 0x0000, 0x0003, 0x0003, 0x0001, 0x0002, 0x0000, 0x0001,
		0x0003, 0x0000, 0x0001, 0x0003, 0x0000, 0x0002, 0x0002, 0x0001,
		0x0001, 0x0003, 0x0002, 0x0001, 0x0002, 0x0000, 0x0001, 0x0002,
	},
	/* 3 (s4) */
	{
		0x0001, 0x0003, 0x0003, 0x0002, 0x0002, 0x0003, 0x0001, 0x0001,
		0x0000, 0x0000, 0x0000, 0x0003, 0x0003, 0x0000, 0x0002, 0x0001,
		0x0001, 0x0000, 0x0000, 0x0001, 0x0002, 0x0000, 0x0001, 0x0002,
		0x0003, 0x0001, 0x0002, 0x0002, 0x0000, 0x0002, 0x0003, 0x0003,
		0x0002, 0x0001, 0x0000, 0x0003, 0x0003, 0x0000, 0x0000, 0x0000,
		0x0002, 0x0002, 0x0003, 0x0001, 0x0001, 0x0003, 0x0003, 0x0002,
		0x0003, 0x0003, 0x0001, 0x0000, 0x0001, 0x0001, 0x0002, 0x0003,
		0x0001, 0x0002, 0x0000, 0x0001, 0x0002, 0x0000, 0x0000, 0x0002,
	},
	/* 4 (s5) */
	{
		0x0000, 0x0002, 0x0002, 0x0003, 0x0000, 0x0000, 0x0001, 0x0002,
		0x0001, 0x0000, 0x0002, 0x0001, 0x0003, 0x0003, 0x0000, 0x0001,
		0x0002, 0x0001, 0x0001, 0x0000, 0x0001, 0x0003, 0x0003, 0x0002,
		0x0003, 0x0001, 0x0000, 0x0003, 0x0002, 0x0002, 0x0003, 0x0000,
		0x0000, 0x0003, 0x0000, 0x0002, 0x0001, 0x0002, 0x0003, 0x0001,
		0x0002, 0x0001, 0x0003, 0x0002, 0x0001, 0x0000, 0x0002, 0x0001,
		0x0003, 0x0001, 0x0002, 0x0003, 0x0003, 0x0002, 0x0000, 0x0003,
		0x0002, 0x0000, 0x0000, 0x0002, 0x0001, 0x0000, 0x0003, 0x0003,
	},
	/* 5 (s6) */
	{0x0002, 0x0002, 0x0001, 0x0003, 0x0002, 0x0000, 0x0003, 0x0000,
		0x0003, 0x0001, 0x0000, 0x0002, 0x0000, 0x0003, 0x0002, 0x0001,
		0x0000, 0x0003, 0x0002, 0x0003, 0x0001, 0x0002, 0x0000, 0x0001,
		0x0003, 0x0000, 0x0001, 0x0003, 0x0000, 0x0002, 0x0001, 0x0002,
		0x0003, 0x0000, 0x0001, 0x0000, 0x0003, 0x0001, 0x0002, 0x0001,
		0x0002, 0x0003, 0x0000, 0x0002, 0x0001, 0x0003, 0x0003, 0x0002,
		0x0001, 0x0003, 0x0002, 0x0001, 0x0003, 0x0002, 0x0000, 0x0003,
		0x0001, 0x0000, 0x0002, 0x0003, 0x0001, 0x0000, 0x0000, 0x0001,
	},
	/* 6 (s7) */
	{
		0x0003, 0x0001, 0x0000, 0x0003, 0x0002, 0x0003, 0x0000, 0x0002,
		0x0000, 0x0002, 0x0003, 0x0001, 0x0003, 0x0001, 0x0001, 0x0000,
		0x0002, 0x0002, 0x0003, 0x0001, 0x0001, 0x0000, 0x0002, 0x0003,
		0x0001, 0x0000, 0x0000, 0x0002, 0x0002, 0x0003, 0x0001, 0x0000,
		0x0001, 0x0000, 0x0003, 0x0001, 0x0000, 0x0002, 0x0001, 0x0001,
		0x0003, 0x0000, 0x0002, 0x0002, 0x0002, 0x0002, 0x0000, 0x0003,
		0x0000, 0x0003, 0x0000, 0x0002, 0x0002, 0x0003, 0x0003, 0x0000,
		0x0003, 0x0001, 0x0001, 0x0001, 0x0001, 0x0000, 0x0002, 0x0003,
	},
	/* 7 (s8) */
	{0x0000, 0x0003, 0x0003, 0x0000, 0x0000, 0x0003, 0x0002, 0x0001,
		0x0003, 0x0000, 0x0000, 0x0003, 0x0002, 0x0001, 0x0003, 0x0002,
		0x0001, 0x0002, 0x0002, 0x0001, 0x0003, 0x0001, 0x0001, 0x0002,
		0x0001, 0x0000, 0x0002, 0x0003, 0x0000, 0x0002, 0x0001, 0x0000,
		0x0001, 0x0000, 0x0000, 0x0003, 0x0003, 0x0003, 0x0003, 0x0002,
		0x0002, 0x0001, 0x0001, 0x0000, 0x0001, 0x0002, 0x0002, 0x0001,
		0x0002, 0x0003, 0x0003, 0x0001, 0x0000, 0x0000, 0x0002, 0x0003,
		0x0000, 0x0002, 0x0001, 0x0000, 0x0003, 0x0001, 0x0000, 0x0002,
	},
}

var stable [TSIZE]uint16

var lookupmasks = [4][3]uint16{
	{0x0036, 0x06C0, 0x6900},
	{0x5048, 0x2106, 0x8411},
	{0x8601, 0x4828, 0x10C4},
	{0x2980, 0x9011, 0x022A},
}

var outputmasks = [4]uint16{
	0x000F,
	0x00F0,
	0x3300,
	0xCC00,
}

func mcgInit() {
	sbits := [8][6]int{
		{2, 5, 6, 9, 11, 13},
		{1, 4, 7, 10, 8, 14},
		{3, 6, 8, 13, 0, 15},
		{12, 14, 1, 2, 4, 10},
		{0, 10, 3, 14, 6, 12},
		{7, 8, 12, 15, 1, 5},
		{9, 15, 5, 11, 2, 7},
		{11, 13, 0, 4, 3, 9},
	}

	for i := uint32(0); i < TSIZE; i++ {
		stable[i] = 0
		for j := 0; j < 8; j++ {
			index := ((i >> sbits[j][0]) & 1) |
				(((i >> sbits[j][1]) & 1) << 1) |
				(((i >> sbits[j][2]) & 1) << 2) |
				(((i >> sbits[j][3]) & 1) << 3) |
				(((i >> sbits[j][4]) & 1) << 4) |
				(((i >> sbits[j][5]) & 1) << 5)
			stable[i] |= sboxes[j][index]
		}
	}
}

func mcgKeyset(key []byte, ek *mcgKey) {
	var k [2][8]byte

	mcgInit()

	copy(k[0][:], key[:8])
	copy(k[1][:], key[8:16])

	for i := 0; i < KSIZE; i++ {
		ek.val[i] = 0
	}

	for i := 0; i < 2; i++ {
		for j := 0; j < 32; j++ {
			mcgBlockEncrypt(k[i][:], ek)
			ek.val[j*3] ^= uint16(k[i][0]) | (uint16(k[i][1]) << 8)
			ek.val[j*3+1] ^= uint16(k[i][2]) | (uint16(k[i][3]) << 8)
			ek.val[j*3+2] ^= uint16(k[i][4]) | (uint16(k[i][5]) << 8)
		}
	}
}

func mcgBlockEncrypt(blk []byte, key *mcgKey) {
	var r [4]uint16
	var a, b, c uint16
	var ek = key.val[:]
	ekIndex := 0

	r[0] = binary.BigEndian.Uint16(blk[0:2])
	r[1] = binary.BigEndian.Uint16(blk[2:4])
	r[2] = binary.BigEndian.Uint16(blk[4:6])
	r[3] = binary.BigEndian.Uint16(blk[6:8])

	for i := 0; i < ROUNDS/4; i++ {
		a = r[1] ^ ek[ekIndex]
		ekIndex++
		b = r[2] ^ ek[ekIndex]
		ekIndex++
		c = r[3] ^ ek[ekIndex]
		ekIndex++
		r[0] ^= computeSBoxes(a, b, c)

		a = r[2] ^ ek[ekIndex]
		ekIndex++
		b = r[3] ^ ek[ekIndex]
		ekIndex++
		c = r[0] ^ ek[ekIndex]
		ekIndex++
		r[1] ^= computeSBoxes(a, b, c)

		a = r[3] ^ ek[ekIndex]
		ekIndex++
		b = r[0] ^ ek[ekIndex]
		ekIndex++
		c = r[1] ^ ek[ekIndex]
		ekIndex++
		r[2] ^= computeSBoxes(a, b, c)

		a = r[0] ^ ek[ekIndex]
		ekIndex++
		b = r[1] ^ ek[ekIndex]
		ekIndex++
		c = r[2] ^ ek[ekIndex]
		ekIndex++
		r[3] ^= computeSBoxes(a, b, c)
	}

	binary.BigEndian.PutUint16(blk[0:2], r[0])
	binary.BigEndian.PutUint16(blk[2:4], r[1])
	binary.BigEndian.PutUint16(blk[4:6], r[2])
	binary.BigEndian.PutUint16(blk[6:8], r[3])
}

func computeSBoxes(a, b, c uint16) uint16 {
	var result uint16
	result |= outputmasks[0] & stable[(a&lookupmasks[0][0])|(b&lookupmasks[0][1])|(c&lookupmasks[0][2])]
	result |= outputmasks[1] & stable[(a&lookupmasks[1][0])|(b&lookupmasks[1][1])|(c&lookupmasks[1][2])]
	result |= outputmasks[2] & stable[(a&lookupmasks[2][0])|(b&lookupmasks[2][1])|(c&lookupmasks[2][2])]
	result |= outputmasks[3] & stable[(a&lookupmasks[3][0])|(b&lookupmasks[3][1])|(c&lookupmasks[3][2])]
	return result
}

func computeSBoxesDecrypt(a, b, c uint16) uint16 {
	var result uint16
	result |= outputmasks[0] & stable[(a&lookupmasks[0][0])|(b&lookupmasks[0][1])|(c&lookupmasks[0][2])]
	result |= outputmasks[1] & stable[(a&lookupmasks[1][0])|(b&lookupmasks[1][1])|(c&lookupmasks[1][2])]
	result |= outputmasks[2] & stable[(a&lookupmasks[2][0])|(b&lookupmasks[2][1])|(c&lookupmasks[2][2])]
	result |= outputmasks[3] & stable[(a&lookupmasks[3][0])|(b&lookupmasks[3][1])|(c&lookupmasks[3][2])]
	return result
}

func mcgBlockDecrypt(blk []byte, key *mcgKey) {
	var r [4]uint16
	var a, b, c uint16

	r[0] = binary.LittleEndian.Uint16(blk[0:2])
	r[1] = binary.LittleEndian.Uint16(blk[2:4])
	r[2] = binary.LittleEndian.Uint16(blk[4:6])
	r[3] = binary.LittleEndian.Uint16(blk[6:8])

	ek := key.val[:]
	ekIndex := KSIZE

	for i := 0; i < ROUNDS/4; i++ {
		ekIndex--
		c = r[2] ^ ek[ekIndex]
		ekIndex--
		b = r[1] ^ ek[ekIndex]
		ekIndex--
		a = r[0] ^ ek[ekIndex]
		r[3] ^= computeSBoxesDecrypt(a, b, c)

		ekIndex--
		c = r[1] ^ ek[ekIndex]
		ekIndex--
		b = r[0] ^ ek[ekIndex]
		ekIndex--
		a = r[3] ^ ek[ekIndex]
		r[2] ^= computeSBoxesDecrypt(a, b, c)

		ekIndex--
		c = r[0] ^ ek[ekIndex]
		ekIndex--
		b = r[3] ^ ek[ekIndex]
		ekIndex--
		a = r[2] ^ ek[ekIndex]
		r[1] ^= computeSBoxesDecrypt(a, b, c)

		ekIndex--
		c = r[3] ^ ek[ekIndex]
		ekIndex--
		b = r[2] ^ ek[ekIndex]
		ekIndex--
		a = r[1] ^ ek[ekIndex]
		r[0] ^= computeSBoxesDecrypt(a, b, c)
	}

	binary.LittleEndian.PutUint16(blk[0:2], r[0])
	binary.LittleEndian.PutUint16(blk[2:4], r[1])
	binary.LittleEndian.PutUint16(blk[4:6], r[2])
	binary.LittleEndian.PutUint16(blk[6:8], r[3])
}

// Пример использования
//func main() {
//	// Исходный 16-байтовый ключ
//	key := []byte("thisisasecretkey")
//
//	// Создаем и инициализируем расширенный ключ
//	var ek mcgKey
//	mcgKeyset(key, &ek)
//
//	// Шифруемый блок (8 байт)
//	plaintext := []byte("plaintext")
//
//	// Буфер для хранения шифртекста
//	ciphertext := make([]byte, 8)
//	copy(ciphertext, plaintext)
//
//	// Шифрование
//	mcgBlockEncrypt(ciphertext, &ek)
//	fmt.Printf("Encrypted: %x\n", ciphertext)
//
//	// Дешифрование
//	mcgBlockDecrypt(ciphertext, &ek)
//	fmt.Printf("Decrypted: %s\n", ciphertext)
//}
