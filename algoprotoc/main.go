package algoprotoc

//
//import (
//	"encoding/hex"
//	"flag"
//	"fmt"
//	"iSFourthCourseProject/algoprotoc"
//	"os"
//)
//
//// Предполагается, что остальные части вашего кода (CryptoSymmetricContext, MacGuffin, RC5, CipherMode, PaddingMode и т.д.) находятся в тех же файлах и правильно реализованы.
//
//func main() {
//	// Определение флагов командной строки
//	algorithm := flag.String("algorithm", "macguffin", "Choose encryption algorithm: macguffin or rc5")
//	mode := flag.String("mode", "ECB", "Encryption mode: ECB, CBC, CFB, OFB, CTR, PCBC, RandomDelta")
//	padding := flag.String("padding", "PKCS7", "Padding mode: Zeros, ANSIX923, PKCS7, ISO10126")
//	key := flag.String("key", "1234567890abcdef", "Encryption key (16 bytes for MacGuffin, 16/24/32 bytes for RC5)")
//	iv := flag.String("iv", "", "Initialization vector (IV) in hex, required for CBC, CFB, OFB, CTR modes")
//	input := flag.String("input", "input.txt", "Path to input file")
//	output := flag.String("output", "output.dat", "Path to output file")
//	decrypt := flag.Bool("decrypt", false, "Set to true for decryption")
//	flag.Parse()
//
//	// Проверка длины ключа
//	if len(*key) != 16 && len(*key) != 24 && len(*key) != 32 {
//		fmt.Println("Invalid key size. For MacGuffin, use 16 bytes. For RC5, use 16, 24, or 32 bytes.")
//		os.Exit(1)
//	}
//
//	// Парсинг режима шифрования
//	var cipherMode algoprotoc.CipherMode
//	switch *mode {
//	case "ECB":
//		cipherMode = algoprotoc.ModeECB
//	case "CBC":
//		cipherMode = algoprotoc.ModeCBC
//	case "CFB":
//		cipherMode = algoprotoc.ModeCFB
//	case "OFB":
//		cipherMode = algoprotoc.ModeOFB
//	case "CTR":
//		cipherMode = algoprotoc.ModeCTR
//	case "PCBC":
//		cipherMode = algoprotoc.ModePCBC
//	case "RandomDelta":
//		cipherMode = algoprotoc.ModeRandomDelta
//	default:
//		fmt.Println("Invalid encryption mode. Choose from: ECB, CBC, CFB, OFB, CTR, PCBC, RandomDelta")
//		os.Exit(1)
//	}
//
//	// Парсинг режима набивки
//	var paddingMode algoprotoc.PaddingMode
//	switch *padding {
//	case "Zeros":
//		paddingMode = algoprotoc.PaddingZeros
//	case "ANSIX923":
//		paddingMode = algoprotoc.PaddingANSIX923
//	case "PKCS7":
//		paddingMode = algoprotoc.PaddingPKCS7
//	case "ISO10126":
//		paddingMode = algoprotoc.PaddingISO10126
//	default:
//		fmt.Println("Invalid padding mode. Choose from: Zeros, ANSIX923, PKCS7, ISO10126")
//		os.Exit(1)
//	}
//
//	var expectedIVSize int
//	switch *algorithm {
//	case "macguffin":
//		expectedIVSize = 8
//	case "rc5":
//		expectedIVSize = 16
//	default:
//		fmt.Println("Invalid algorithm.")
//	}
//
//	// Парсинг IV, если требуется
//	var ivBytes []byte
//	if cipherMode != algoprotoc.ModeECB && cipherMode != algoprotoc.ModeRandomDelta {
//		if len(*iv) == 0 {
//			fmt.Println("IV is required for selected encryption mode.")
//			os.Exit(1)
//		}
//		// Предполагается, что IV предоставляется в формате hex
//		var err error
//		ivBytes, err = hex.DecodeString(*iv)
//		if err != nil {
//			fmt.Println("Invalid IV format. Provide IV as a hex string.")
//			os.Exit(1)
//		}
//		// Проверка длины IV
//		//expectedIVSize := 16 // Для 128-битных блоков
//		if len(ivBytes) != expectedIVSize {
//			fmt.Printf("Invalid IV size. Expected %d bytes, got %d bytes.\n", expectedIVSize, len(ivBytes))
//			os.Exit(1)
//		}
//	}
//
//	// Выбор алгоритма
//	var cipher algoprotoc.SymmetricCipher
//	switch *algorithm {
//	case "macguffin":
//		cipher = algoprotoc.NewMacGuffinCipher()
//	case "rc5":
//		cipher = algoprotoc.NewRC5()
//	default:
//		fmt.Println("Invalid algorithm. Choose 'macguffin' or 'rc5'.")
//		os.Exit(1)
//	}
//
//	// Установка ключа
//	if err := cipher.SetKey([]byte(*key)); err != nil {
//		fmt.Printf("Failed to set key: %v\n", err)
//		os.Exit(1)
//	}
//
//	// Определение размера блока
//	var blockSize int
//	switch *algorithm {
//	case "macguffin":
//		if len(*key) != 16 {
//			fmt.Println("Invalid key size for MacGuffin. Use 16 bytes.")
//			os.Exit(1)
//		}
//		blockSize = 8 // MacGuffin использует блоки по 8 байт
//	case "rc5":
//		rc5, ok := cipher.(*algoprotoc.RC5)
//		if !ok {
//			fmt.Println("Failed to assert RC5Cipher type")
//			os.Exit(1)
//		}
//		blockSize = int(rc5.w) / 4 // Для w=32 -> 8 байт, для w=64 -> 16 байт
//	default:
//		fmt.Println("Invalid algorithm.")
//		os.Exit(1)
//	}
//
//	// Создание контекста
//	context, err := algoprotoc.NewCryptoContext(
//		[]byte(*key),
//		cipher,
//		cipherMode,
//		paddingMode,
//		ivBytes,
//		blockSize,
//	)
//	if err != nil {
//		fmt.Printf("Failed to create context: %v\n", err)
//		os.Exit(1)
//	}
//
//	// Чтение входного файла
//	inputData, err := os.ReadFile(*input)
//	if err != nil {
//		fmt.Printf("Failed to read input file: %v\n", err)
//		os.Exit(1)
//	}
//
//	// Выполнение шифрования или дешифрования асинхронно
//	if *decrypt {
//		decryptedChan, errChan := context.DecryptAsync(inputData)
//		select {
//		case decryptedData := <-decryptedChan:
//			// Запись расшифрованных данных в выходной файл
//			if err := os.WriteFile(*output, decryptedData, 0644); err != nil {
//				fmt.Printf("Failed to write output file: %v\n", err)
//				os.Exit(1)
//			}
//			fmt.Println("Decryption completed successfully!")
//		case err := <-errChan:
//			fmt.Printf("Decryption failed: %v\n", err)
//			os.Exit(1)
//		}
//	} else {
//		encryptedChan, errChan := context.EncryptAsync(inputData)
//		select {
//		case encryptedData := <-encryptedChan:
//			// Запись зашифрованных данных в выходной файл
//			if err := os.WriteFile(*output, encryptedData, 0644); err != nil {
//				fmt.Printf("Failed to write output file: %v\n", err)
//				os.Exit(1)
//			}
//			fmt.Println("Encryption completed successfully!")
//		case err := <-errChan:
//			fmt.Printf("Encryption failed: %v\n", err)
//			os.Exit(1)
//		}
//	}
//}
