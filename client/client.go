package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	"iSFourthCourseProject/algoprotoc"
	chatpb "iSFourthCourseProject/proto/chatpb"

	"github.com/google/uuid"
)

func main() {
	// Установка соединения с сервером gRPC
	conn, err := grpc.Dial("localhost:6472",
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1024*1024*500),
			grpc.MaxCallSendMsgSize(1024*1024*500),
		),
	)

	if err != nil {
		log.Fatalf("Не удалось подключиться к серверу: %v", err)
	}
	defer conn.Close()
	exitChan := make(chan bool)

	client := chatpb.NewChatServiceClient(conn)

	fmt.Print("Введите ID комнаты (или нажмите Enter для создания новой): ")
	reader := bufio.NewReader(os.Stdin)
	roomID, _ := reader.ReadString('\n')
	roomID = strings.TrimSpace(roomID)

	var algorithmName, mode, padding string
	var prime *big.Int
	if roomID == "" {
		fmt.Print("Выберите алгоритм (macguffin или rc5): ")
		algorithmName, _ = reader.ReadString('\n')
		algorithmName = strings.TrimSpace(algorithmName)

		fmt.Print("Выберите режим шифрования (ECB, CBC, CFB, OFB, CTR, RandomDelta): ")
		mode, _ = reader.ReadString('\n')
		mode = strings.TrimSpace(mode)

		fmt.Print("Выберите режим набивки (Zeros, ANSIX923, PKCS7, ISO10126): ")
		padding, _ = reader.ReadString('\n')
		padding = strings.TrimSpace(padding)

		prime, _ = algoprotoc.GeneratePrime(2048)
		primeHex := hex.EncodeToString(prime.Bytes())

		// Создание комнаты
		createRoomResp, err := client.CreateRoom(context.Background(), &chatpb.CreateRoomRequest{
			Algorithm: algorithmName, //
			Mode:      mode,
			Padding:   padding,
			Prime:     primeHex,
		})
		if err != nil {
			log.Fatalf("Ошибка при создании комнаты: %v", err)
		}
		roomID = createRoomResp.GetRoomId()
		fmt.Printf("Комната создана с ID: %s\n", roomID)
	} else {
		fmt.Printf("Присоединяемся к существующей комнате с ID: %s\n", roomID)

		// Получение параметров комнаты
		getRoomResp, err := client.GetRoom(context.Background(), &chatpb.GetRoomRequest{
			RoomId: roomID,
		})
		if err != nil {
			log.Fatalf("Ошибка при получении параметров комнаты: %v", err)
		}
		algorithmName = getRoomResp.GetAlgorithm()
		mode = getRoomResp.GetMode()
		padding = getRoomResp.GetPadding()
		primeBytes, _ := hex.DecodeString(getRoomResp.GetPrime())
		prime = new(big.Int).SetBytes(primeBytes)
	}

	clientID := uuid.New().String()

	// Присоединение к комнате
	joinResp, err := client.JoinRoom(context.Background(), &chatpb.JoinRoomRequest{
		RoomId:   roomID,
		ClientId: clientID,
	})
	if err != nil || !joinResp.GetSuccess() {
		log.Fatalf("Ошибка при присоединении к комнате: %v", err)
	}
	fmt.Println("Успешно присоединились к комнате")

	generator := big.NewInt(2)

	// Генерация ключей Диффи-Хеллмана
	privateKey, _ := algoprotoc.GeneratePrivateKey(prime)
	publicKey := algoprotoc.GeneratePublicKey(generator, privateKey, prime)
	publicKeyHex := hex.EncodeToString(publicKey.Bytes())

	// Отправка публичного ключа на сервер
	_, err = client.SendPublicKey(context.Background(), &chatpb.SendPublicKeyRequest{
		RoomId:    roomID,
		ClientId:  clientID,
		PublicKey: publicKeyHex,
	})
	if err != nil {
		log.Fatalf("Ошибка при отправке публичного ключа: %v", err)
	}

	var cipherContextMutex sync.Mutex
	var cipherContext *algoprotoc.CryptoContext

	// Мапа для хранения публичных ключей других клиентов
	otherPublicKeys := make(map[string]string)
	var sharedKeyComputed bool = false

	// Запуск горутины для получения сообщений
	go receiveMessages(client, roomID, clientID, &cipherContext,
		&cipherContextMutex, &otherPublicKeys, &sharedKeyComputed, privateKey, prime, algorithmName, mode, padding)

	go func() {
		<-exitChan
		fmt.Println("Завершаем работу программы...")
		os.Exit(0)
	}()

	// Дополнительный вызов GetPublicKeys после отправки публичного ключа
	go func() {
		for {
			if sharedKeyComputed {
				break
			}

			getKeysResp, err := client.GetPublicKeys(context.Background(), &chatpb.GetPublicKeysRequest{
				RoomId: roomID,
			})
			if err != nil {
				log.Printf("Ошибка при получении публичных ключей: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}

			for _, clientKey := range getKeysResp.GetPublicKeys() {
				if clientKey.GetClientId() != clientID && clientKey.GetPublicKey() != "" {
					otherPublicKeyHex := clientKey.GetPublicKey()
					otherPublicKeyBytes, err := hex.DecodeString(otherPublicKeyHex)
					if err != nil {
						log.Printf("Ошибка декодирования публичного ключа: %v", err)
						continue
					}
					otherPublicKey := new(big.Int).SetBytes(otherPublicKeyBytes)

					// Вычисляем общий секретный ключ
					sharedKey := algoprotoc.GenerateSharedKey(privateKey, otherPublicKey, prime)
					hashedSharedKey := algoprotoc.HashSharedKey(sharedKey)

					// Инициализируем cipherContext
					initCipher(hashedSharedKey, &cipherContext, &cipherContextMutex, algorithmName, mode, padding)
					sharedKeyComputed = true
					break
				}
			}

			if !sharedKeyComputed {
				time.Sleep(2 * time.Second)
			}
		}
	}()

	// Цикл отправки сообщений
	for {
		fmt.Print("Введите сообщение (или 'send-file' для отправки файла): ")
		message, _ := reader.ReadString('\n')
		message = strings.TrimSpace(message)

		// Отправка файла
		if message == "send-file" {
			sendFile(client, roomID, clientID, cipherContext)
			continue
		}

		// Проверка на пустое сообщение
		if message == "" {
			continue
		}

		// Обработка команд
		if strings.HasPrefix(message, "/") {
			switch message {
			case "/close":
				closeResp, err := client.CloseRoom(context.Background(), &chatpb.CloseRoomRequest{
					RoomId: roomID,
				})
				if err != nil || !closeResp.GetSuccess() {
					fmt.Printf("Ошибка при удалении комнаты: %v\n", err)
				} else {
					fmt.Println("Комната успешно удалена.")
				}
				exitChan <- true
				return
			case "/exit":
				// Выход из комнаты
				_, err := client.LeaveRoom(context.Background(), &chatpb.LeaveRoomRequest{
					RoomId:   roomID,
					ClientId: clientID,
				})
				if err != nil {
					fmt.Printf("Ошибка при выходе из комнаты: %v\n", err)
				} else {
					fmt.Println("Вы вышли из комнаты.")
				}
				exitChan <- true
				return
			default:
				fmt.Println("Неизвестная команда. Доступные команды: /close, /exit")
				continue
			}
		}

		if !sharedKeyComputed {
			fmt.Println("Контекст шифрования не инициализирован. Подождите завершения обмена ключами.")
			continue
		}

		cipherContextMutex.Lock()
		encryptedMessage, err := cipherContext.Encrypt([]byte(message))
		cipherContextMutex.Unlock()
		if err != nil {
			log.Fatalf("Ошибка при шифровании сообщения: %v", err)
		}

		_, err = client.SendMessage(context.Background(), &chatpb.SendMessageRequest{
			RoomId:           roomID,
			ClientId:         clientID,
			EncryptedMessage: encryptedMessage,
		})
		if err != nil {
			log.Fatalf("Ошибка при отправке сообщения: %v", err)
		}
		fmt.Println("Сообщение отправлено")
	}
}

func receiveMessages(client chatpb.ChatServiceClient,
	roomID, clientID string,
	cipherContext **algoprotoc.CryptoContext,
	cipherContextMutex *sync.Mutex,
	otherPublicKeys *map[string]string,
	sharedKeyComputed *bool,
	privateKey *big.Int, prime *big.Int,
	algorithmName, mode, padding string,
) {
	stream, err := client.ReceiveMessages(context.Background(), &chatpb.ReceiveMessagesRequest{
		RoomId:   roomID,
		ClientId: clientID,
	})
	if err != nil {
		log.Fatalf("Ошибка при получении сообщений: %v", err)
	}

	fileChunks := make(map[string][][]byte)
	fileChunkCount := make(map[string]int)
	fileTotalChunks := make(map[string]int)
	mutex := &sync.Mutex{}

	for {
		msg, err := stream.Recv()
		if err != nil {
			log.Fatalf("Ошибка при получении сообщения из потока: %v", err)
		}

		if msg.GetType() == "public_key" {
			senderID := msg.GetSenderId()
			publicKeyHex := string(msg.GetEncryptedMessage())

			if senderID == clientID {
				continue
			}

			(*otherPublicKeys)[senderID] = publicKeyHex
			fmt.Printf("Получен публичный ключ от клиента %s\n", senderID)

			if len(*otherPublicKeys) >= 1 && !(*sharedKeyComputed) {
				otherPublicKeyBytes, err := hex.DecodeString(publicKeyHex)
				if err != nil {
					log.Printf("Ошибка декодирования публичного ключа: %v", err)
					continue
				}
				otherPublicKey := new(big.Int).SetBytes(otherPublicKeyBytes)

				// Вычисляем общий секретный ключ
				sharedKey := algoprotoc.GenerateSharedKey(privateKey, otherPublicKey, prime)
				hashedSharedKey := algoprotoc.HashSharedKey(sharedKey)

				fmt.Printf("Общий секретный ключ вычислен\n")

				initCipher(hashedSharedKey, cipherContext, cipherContextMutex, algorithmName, mode, padding)
				*sharedKeyComputed = true
			}

			continue
		}

		if msg.GetType() == "message" {
			senderID := msg.GetSenderId()
			encryptedMessage := msg.GetEncryptedMessage()

			cipherContextMutex.Lock()
			if *cipherContext == nil {
				cipherContextMutex.Unlock()
				fmt.Println("Контекст шифрования не инициализирован.")
				continue
			}
			decryptedMessage, err := (*cipherContext).Decrypt(encryptedMessage)
			cipherContextMutex.Unlock()
			if err != nil {
				fmt.Printf("Ошибка при расшифровке сообщения: %v\n", err)
				continue
			}
			fmt.Printf("Сообщение от %s: %s\n", senderID, string(decryptedMessage))
		}

		if msg.GetType() == "file" {
			senderID := msg.GetSenderId()
			encryptedChunk := msg.GetEncryptedMessage()
			fileName := msg.GetFileName()
			chunkIndex := int(msg.GetChunkIndex())
			totalChunks := int(msg.GetTotalChunks())

			fmt.Printf("Получен файл: %s от клиента %s (Chunk %d/%d)\n", fileName, senderID, chunkIndex+1, totalChunks)

			fileKey := senderID + "_" + fileName

			cipherContextMutex.Lock()
			if *cipherContext == nil {
				cipherContextMutex.Unlock()
				fmt.Println("Контекст шифрования не инициализирован.")
				continue
			}
			decryptedChunk, err := (*cipherContext).Decrypt(encryptedChunk)
			cipherContextMutex.Unlock()
			if err != nil {
				fmt.Printf("Ошибка при расшифровке фрагмента файла от %s: %v\n", senderID, err)
				continue
			}

			mutex.Lock()
			if _, exists := fileChunks[fileKey]; !exists {
				fileChunks[fileKey] = make([][]byte, totalChunks)
				fileChunkCount[fileKey] = 0
				fileTotalChunks[fileKey] = totalChunks
			}

			fileChunks[fileKey][chunkIndex] = decryptedChunk
			fileChunkCount[fileKey]++

			if fileChunkCount[fileKey] == fileTotalChunks[fileKey] {
				var fileData []byte
				for _, chunk := range fileChunks[fileKey] {
					fileData = append(fileData, chunk...)
				}

				clientFolder := filepath.Join("received_files", senderID)
				if _, err := os.Stat(clientFolder); os.IsNotExist(err) {
					err := os.MkdirAll(clientFolder, 0755)
					if err != nil {
						fmt.Printf("Ошибка при создании папки клиента: %v\n", err)
						mutex.Unlock()
						continue
					}
				}

				baseFileName := filepath.Base(fileName)
				outputPath := filepath.Join(clientFolder, baseFileName)

				ext := filepath.Ext(outputPath)
				baseName := strings.TrimSuffix(baseFileName, ext)
				counter := 1
				for {
					if _, err := os.Stat(outputPath); err == nil {
						outputPath = filepath.Join(clientFolder, fmt.Sprintf("%s(%d)%s", baseName, counter, ext))
						counter++
					} else {
						break
					}
				}

				fmt.Printf("Сохранение файла как: %s\n", outputPath)

				err = os.WriteFile(outputPath, fileData, 0644)
				if err != nil {
					fmt.Printf("Ошибка сохранения файла: %v\n", err)
					mutex.Unlock()
					continue
				}

				fmt.Printf("Файл от %s сохранен как %s\n", senderID, outputPath)

				delete(fileChunks, fileKey)
				delete(fileChunkCount, fileKey)
				delete(fileTotalChunks, fileKey)
			}
			mutex.Unlock()
		}
	}
}

func sendFile(client chatpb.ChatServiceClient, roomID, clientID string, cipherContext *algoprotoc.CryptoContext) {
	fmt.Print("Введите путь к файлу для отправки: ")
	reader := bufio.NewReader(os.Stdin)
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	baseFileName := filepath.Base(filePath)

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Ошибка чтения файла: %v\n", err)
		return
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Ошибка при получении текущего каталога:", err)
	} else {
		fmt.Println("Текущий рабочий каталог:", cwd)
	}

	encryptedData, err := cipherContext.Encrypt(fileData)
	if err != nil {
		fmt.Printf("Ошибка при шифровании файла: %v\n", err)
		return
	}

	_, err = client.SendMessage(context.Background(), &chatpb.SendMessageRequest{
		RoomId:           roomID,
		ClientId:         clientID,
		MessageType:      "file",
		FileName:         baseFileName,
		EncryptedMessage: encryptedData,
	})
	if err != nil {
		fmt.Printf("Ошибка при отправке файла: %v\n", err)
		return
	}

	fmt.Println("Файл успешно отправлен.")
}

func initCipher(hashedSharedKey []byte, cipherContext **algoprotoc.CryptoContext, cipherContextMutex *sync.Mutex, algorithmName, mode, padding string) {
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

	cipherContextMutex.Lock()
	defer cipherContextMutex.Unlock()
	cipherCtx, err := algoprotoc.NewCryptoContext(
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
	*cipherContext = cipherCtx
}
