package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/streadway/amqp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	chatpb "iSFourthCourseProject/proto/chatpb"
)

// Структура клиента
type Client struct {
	ClientID  string
	PublicKey string // Публичный ключ в формате hex
	SharedKey []byte
}

// Структура комнаты
type ChatRoom struct {
	RoomID    string
	Algorithm string
	Mode      string
	Padding   string
	Prime     string
	Clients   map[string]*Client
	mutex     sync.RWMutex
}

// Структура сервера
type ChatServer struct {
	chatpb.UnimplementedChatServiceServer
	redisStore      *RedisStore
	rooms           map[string]*ChatRoom
	roomsMutex      sync.RWMutex
	rabbitMQConn    *amqp.Connection
	rabbitMQChannel *amqp.Channel
	db              *sql.DB
}

// Создание нового сервера
func NewChatServer() *ChatServer {
	var conn *amqp.Connection
	var err error
	for i := 0; i < 10; i++ {
		conn, err = amqp.Dial("amqp://guest:guest@rabbitmq-1:5672/")
		if err == nil {
			break
		}
		log.Println("RabbitMQ не готов, повторная попытка через 5 секунд...")
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		log.Fatalf("Не удалось подключиться к RabbitMQ: %v", err)
	}

	channel, err := conn.Channel()
	if err != nil {
		log.Fatalf("Не удалось открыть канал RabbitMQ: %v", err)
	}

	// Инициализация RedisStore
	redisStore := NewRedisStore("redis-2:6379", "", 0)

	// Подключение к PostgreSQL
	db, err := sql.Open("postgres", "postgres://user1:password@postgres:5432/mydb1?sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	return &ChatServer{
		redisStore:      redisStore,
		rooms:           make(map[string]*ChatRoom),
		rabbitMQConn:    conn,
		rabbitMQChannel: channel,
		db:              db,
	}
}

func generateRoomID() string {
	bytes := make([]byte, 4)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatalf("Не удалось сгенерировать случайные байты: %v", err)
	}
	return hex.EncodeToString(bytes)
}

// Метод создания комнаты
func (s *ChatServer) CreateRoom(ctx context.Context, req *chatpb.CreateRoomRequest) (*chatpb.CreateRoomResponse, error) {
	roomID := generateRoomID()
	s.roomsMutex.Lock()
	defer s.roomsMutex.Unlock()

	s.rooms[roomID] = &ChatRoom{
		RoomID:    roomID,
		Algorithm: req.Algorithm,
		Mode:      req.Mode,
		Padding:   req.Padding,
		Prime:     req.Prime,
		Clients:   make(map[string]*Client),
	}

	// Создание комнаты в Redis
	err := s.redisStore.CreateRoom(ctx, roomID, req.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("Не удалось создать комнату в Redis: %v", err)
	}

	err = s.rabbitMQChannel.ExchangeDeclare(
		roomID,
		"fanout",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("Не удалось объявить exchange: %v", err)
	}

	return &chatpb.CreateRoomResponse{
		RoomId: roomID,
	}, nil
}

// Метод получения параметров комнаты
func (s *ChatServer) GetRoom(ctx context.Context, req *chatpb.GetRoomRequest) (*chatpb.GetRoomResponse, error) {
	roomID := req.GetRoomId()
	s.roomsMutex.RLock()
	defer s.roomsMutex.RUnlock()

	room, ok := s.rooms[roomID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Комната с ID %s не найдена", roomID)
	}

	return &chatpb.GetRoomResponse{
		Algorithm: room.Algorithm,
		Mode:      room.Mode,
		Padding:   room.Padding,
		Prime:     room.Prime,
	}, nil
}

// Метод закрытия комнаты
func (s *ChatServer) CloseRoom(ctx context.Context, req *chatpb.CloseRoomRequest) (*chatpb.CloseRoomResponse, error) {
	s.roomsMutex.Lock()
	defer s.roomsMutex.Unlock()

	room, exists := s.rooms[req.RoomId]
	if !exists {
		return &chatpb.CloseRoomResponse{
			Success: false,
		}, fmt.Errorf("Комната не найдена")
	}

	err := s.rabbitMQChannel.ExchangeDelete(
		room.RoomID,
		false,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("Не удалось удалить exchange: %v", err)
	}

	// Удаление комнаты из RedisStore
	err = s.redisStore.DeleteRoom(ctx, req.RoomId)
	if err != nil {
		return nil, fmt.Errorf("Не удалось удалить комнату из Redis: %v", err)
	}

	delete(s.rooms, req.RoomId)

	return &chatpb.CloseRoomResponse{
		Success: true,
	}, nil
}

// Метод присоединения к комнате
func (s *ChatServer) JoinRoom(ctx context.Context, req *chatpb.JoinRoomRequest) (*chatpb.JoinRoomResponse, error) {
	s.roomsMutex.RLock()
	room, exists := s.rooms[req.RoomId]
	s.roomsMutex.RUnlock()
	if !exists {
		return &chatpb.JoinRoomResponse{
			Success: false,
			Error:   "Комната не найдена",
		}, nil
	}

	room.mutex.Lock()
	defer room.mutex.Unlock()

	// Проверка, достигнуто ли максимальное количество клиентов
	if len(room.Clients) >= 2 {
		return &chatpb.JoinRoomResponse{
			Success: false,
			Error:   "Комната уже заполнена",
		}, nil
	}

	if _, exists := room.Clients[req.ClientId]; exists {
		return &chatpb.JoinRoomResponse{
			Success: false,
			Error:   "Клиент уже присоединился к комнате",
		}, nil
	}

	room.Clients[req.ClientId] = &Client{
		ClientID:  req.ClientId,
		PublicKey: "",
	}

	// Добавление клиента в RedisStore
	err := s.redisStore.AddClientToRoom(ctx, req.RoomId, req.ClientId)
	if err != nil {
		return &chatpb.JoinRoomResponse{
			Success: false,
			Error:   "Не удалось добавить клиента в комнату",
		}, nil
	}

	log.Printf("Клиент %s присоединился к комнате %s", req.ClientId, req.RoomId)

	return &chatpb.JoinRoomResponse{
		Success: true,
	}, nil
}

// Метод выхода из комнаты
func (s *ChatServer) LeaveRoom(ctx context.Context, req *chatpb.LeaveRoomRequest) (*chatpb.LeaveRoomResponse, error) {
	s.roomsMutex.RLock()
	room, exists := s.rooms[req.RoomId]
	s.roomsMutex.RUnlock()
	if !exists {
		return &chatpb.LeaveRoomResponse{
			Success: false,
			Error:   "Комната не найдена",
		}, nil
	}

	room.mutex.Lock()
	defer room.mutex.Unlock()

	if _, exists := room.Clients[req.ClientId]; !exists {
		return &chatpb.LeaveRoomResponse{
			Success: false,
			Error:   "Клиент не найден в комнате",
		}, nil
	}

	delete(room.Clients, req.ClientId)

	// Удаление клиента из RedisStore
	err := s.redisStore.RemoveClientFromRoom(ctx, req.RoomId, req.ClientId)
	if err != nil {
		return &chatpb.LeaveRoomResponse{
			Success: false,
			Error:   "Не удалось удалить клиента из комнаты",
		}, nil
	}

	return &chatpb.LeaveRoomResponse{
		Success: true,
	}, nil
}

// Метод отправки публичного ключа
func (s *ChatServer) SendPublicKey(ctx context.Context, req *chatpb.SendPublicKeyRequest) (*chatpb.SendPublicKeyResponse, error) {
	s.roomsMutex.RLock()
	room, exists := s.rooms[req.RoomId]
	s.roomsMutex.RUnlock()
	if !exists {
		return &chatpb.SendPublicKeyResponse{
			Success: false,
			Error:   "Комната не найдена",
		}, nil
	}

	room.mutex.Lock()
	client, exists := room.Clients[req.ClientId]
	if !exists {
		room.mutex.Unlock()
		return &chatpb.SendPublicKeyResponse{
			Success: false,
			Error:   "Клиент не присоединился к комнате",
		}, nil
	}

	// Сохраняем публичный ключ
	client.PublicKey = req.PublicKey
	room.mutex.Unlock()

	// Сохранение публичного ключа в RedisStore
	err := s.redisStore.SavePublicKey(ctx, req.RoomId, req.ClientId, req.PublicKey)
	if err != nil {
		return &chatpb.SendPublicKeyResponse{
			Success: false,
			Error:   "Не удалось сохранить публичный ключ",
		}, nil
	}

	err = s.rabbitMQChannel.Publish(
		req.RoomId,
		"",
		false,
		false,
		amqp.Publishing{
			ContentType: "application/octet-stream",
			Body:        []byte(req.PublicKey),
			Headers: amqp.Table{
				"type":      "public_key",
				"sender_id": req.ClientId,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Не удалось опубликовать публичный ключ: %v", err)
	}

	// Проверка, все ли клиенты присоединились и отправили свои публичные ключи
	publicKeys, err := s.redisStore.GetPublicKeys(ctx, req.RoomId)
	if err != nil {
		return &chatpb.SendPublicKeyResponse{
			Success: false,
			Error:   "Не удалось получить публичные ключи",
		}, nil
	}

	s.roomsMutex.RLock()
	totalClients := len(s.rooms[req.RoomId].Clients)
	s.roomsMutex.RUnlock()

	if len(publicKeys) >= totalClients {
		log.Printf("Все публичные ключи в комнате %s получены", req.RoomId)
	}

	return &chatpb.SendPublicKeyResponse{
		Success: true,
	}, nil
}

// Метод отправки сообщения
func (s *ChatServer) SendMessage(ctx context.Context, req *chatpb.SendMessageRequest) (*chatpb.SendMessageResponse, error) {
	s.roomsMutex.RLock()
	room, exists := s.rooms[req.RoomId]
	s.roomsMutex.RUnlock()
	if !exists {
		return &chatpb.SendMessageResponse{
			Success: false,
			Error:   "Комната не найдена",
		}, nil
	}

	messageType := "message"
	if req.GetMessageType() == "file" {
		messageType = "file"
	}

	headers := amqp.Table{
		"type":      messageType,
		"sender_id": req.ClientId,
	}
	if messageType == "file" {
		headers["file_name"] = req.GetFileName()

		data := req.EncryptedMessage

		const chunkSize = 256 * 1024 // 256 KB
		totalChunks := (len(data) + chunkSize - 1) / chunkSize

		for i := 0; i < len(data); i += chunkSize {
			end := i + chunkSize
			if end > len(data) {
				end = len(data)
			}

			chunkData := data[i:end]

			chunkHeaders := amqp.Table{
				"type":         messageType,
				"sender_id":    req.ClientId,
				"file_name":    req.GetFileName(),
				"chunk_index":  int32(i / chunkSize),
				"total_chunks": int32(totalChunks),
			}

			err := s.rabbitMQChannel.Publish(
				room.RoomID,
				"",
				false,
				false,
				amqp.Publishing{
					ContentType: "application/octet-stream",
					Body:        chunkData,
					Headers:     chunkHeaders,
				},
			)
			if err != nil {
				return &chatpb.SendMessageResponse{
					Success: false,
					Error:   fmt.Sprintf("Ошибка отправки фрагмента: %v", err),
				}, nil
			}
		}

		return &chatpb.SendMessageResponse{
			Success: true,
		}, nil
	}

	err := s.rabbitMQChannel.Publish(
		room.RoomID,
		"",
		false,
		false,
		amqp.Publishing{
			ContentType: "application/octet-stream",
			Body:        req.EncryptedMessage,
			Headers: amqp.Table{
				"type":      "message",
				"sender_id": req.ClientId,
			},
		},
	)
	if err != nil {
		return &chatpb.SendMessageResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	_, dbErr := s.db.ExecContext(ctx,
		"INSERT INTO messages (room_id, sender_id, encrypted_message) VALUES ($1, $2, $3)",
		req.RoomId, req.ClientId, req.EncryptedMessage)
	if dbErr != nil {
		log.Printf("Failed to insert message into DB: %v", dbErr)
		return &chatpb.SendMessageResponse{
			Success: false,
			Error:   "Не удалось сохранить сообщение в БД",
		}, nil
	}

	return &chatpb.SendMessageResponse{
		Success: true,
	}, nil
}

// Метод получения сообщений
func (s *ChatServer) ReceiveMessages(req *chatpb.ReceiveMessagesRequest, stream chatpb.ChatService_ReceiveMessagesServer) error {
	s.roomsMutex.RLock()
	room, exists := s.rooms[req.RoomId]
	s.roomsMutex.RUnlock()
	if !exists {
		return fmt.Errorf("Комната не найдена")
	}

	// Создание уникального имени очереди для клиента
	queueName := "queue_" + req.ClientId + "_" + uuid.New().String()

	// Объявление очереди
	q, err := s.rabbitMQChannel.QueueDeclare(
		queueName,
		false,
		true,
		false,
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("Не удалось объявить очередь: %v", err)
	}

	err = s.rabbitMQChannel.QueueBind(
		q.Name,
		"",
		room.RoomID,
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("Не удалось привязать очередь: %v", err)
	}

	msgs, err := s.rabbitMQChannel.Consume(
		q.Name,
		"",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("Не удалось подписаться на сообщения: %v", err)
	}

	// Горутина для прослушивания сообщений и отправки клиенту
	done := make(chan bool)

	go func() {
		for msg := range msgs {
			msgType, _ := msg.Headers["type"].(string)
			senderID, _ := msg.Headers["sender_id"].(string)
			fileName, _ := msg.Headers["file_name"].(string)

			if senderID == req.ClientId {
				continue
			}

			var response *chatpb.ReceiveMessagesResponse

			if msgType == "public_key" {
				response = &chatpb.ReceiveMessagesResponse{
					Type:             "public_key",
					SenderId:         senderID,
					EncryptedMessage: msg.Body,
				}
			} else if msgType == "message" {
				response = &chatpb.ReceiveMessagesResponse{
					Type:             "message",
					SenderId:         senderID,
					EncryptedMessage: msg.Body,
				}
			} else if msgType == "file" {
				var chunkIndex int32
				if val, ok := msg.Headers["chunk_index"]; ok {
					switch v := val.(type) {
					case int8:
						chunkIndex = int32(v)
					case int16:
						chunkIndex = int32(v)
					case int32:
						chunkIndex = v
					case int64:
						chunkIndex = int32(v)
					case float32:
						chunkIndex = int32(v)
					case float64:
						chunkIndex = int32(v)
					default:
						log.Printf("Неизвестный тип для chunk_index: %T", v)
						chunkIndex = 0
					}
				} else {
					log.Printf("chunk_index отсутствует в заголовках")
					chunkIndex = 0
				}

				var totalChunks int32
				if val, ok := msg.Headers["total_chunks"]; ok {
					switch v := val.(type) {
					case int8:
						totalChunks = int32(v)
					case int16:
						totalChunks = int32(v)
					case int32:
						totalChunks = v
					case int64:
						totalChunks = int32(v)
					case float32:
						totalChunks = int32(v)
					case float64:
						totalChunks = int32(v)
					default:
						log.Printf("Неизвестный тип для total_chunks: %T", v)
						totalChunks = 1
					}
				} else {
					log.Printf("total_chunks отсутствует в заголовках")
					totalChunks = 1
				}

				response = &chatpb.ReceiveMessagesResponse{
					Type:             "file",
					SenderId:         senderID,
					EncryptedMessage: msg.Body,
					FileName:         fileName,
					ChunkIndex:       chunkIndex,
					TotalChunks:      totalChunks,
				}

				log.Printf("Получено сообщение типа 'file' от %s: %s (Chunk %d/%d)", senderID, fileName, chunkIndex+1, totalChunks)
			} else {
				continue
			}

			if err := stream.Send(response); err != nil {
				log.Printf("Не удалось отправить сообщение клиенту %s: %v", req.ClientId, err)
				done <- true
				return
			}

			log.Printf("Сообщение отправлено клиенту %s", req.ClientId)
		}
	}()

	<-done
	return nil
}

func (s *ChatServer) GetRoomHistory(ctx context.Context, req *chatpb.GetRoomHistoryRequest) (*chatpb.GetRoomHistoryResponse, error) {
	s.roomsMutex.RLock()
	_, exists := s.rooms[req.RoomId]
	s.roomsMutex.RUnlock()
	if !exists {
		return nil, status.Errorf(codes.NotFound, "Комната с ID %s не найдена", req.RoomId)
	}

	rows, err := s.db.QueryContext(ctx, "SELECT sender_id, encrypted_message, created_at FROM messages WHERE room_id = $1 ORDER BY id DESC LIMIT 50", req.RoomId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Не удалось получить историю сообщений: %v", err)
	}
	defer rows.Close()

	var messages []*chatpb.MessageRecord
	for rows.Next() {
		var senderID string
		var encryptedMessage []byte
		var createdAt string

		if err := rows.Scan(&senderID, &encryptedMessage, &createdAt); err != nil {
			return nil, status.Errorf(codes.Internal, "Ошибка при чтении строки: %v", err)
		}

		messages = append(messages, &chatpb.MessageRecord{
			SenderId:         senderID,
			EncryptedMessage: encryptedMessage,
			CreatedAt:        createdAt,
		})
	}

	return &chatpb.GetRoomHistoryResponse{
		Messages: messages,
	}, nil
}

// Метод получения публичных ключей
func (s *ChatServer) GetPublicKeys(ctx context.Context, req *chatpb.GetPublicKeysRequest) (*chatpb.GetPublicKeysResponse, error) {
	s.roomsMutex.RLock()
	room, exists := s.rooms[req.RoomId]
	s.roomsMutex.RUnlock()
	if !exists {
		return nil, status.Errorf(codes.NotFound, "Комната с ID %s не найдена", req.RoomId)
	}

	room.mutex.RLock()
	defer room.mutex.RUnlock()

	var publicKeys []*chatpb.ClientPublicKey
	for clientID, client := range room.Clients {
		if client.PublicKey != "" {
			publicKeys = append(publicKeys, &chatpb.ClientPublicKey{
				ClientId:  clientID,
				PublicKey: client.PublicKey,
			})
		}
	}

	return &chatpb.GetPublicKeysResponse{
		PublicKeys: publicKeys,
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":6472")
	if err != nil {
		log.Fatalf("Не удалось прослушивать порт: %v", err)
	}

	grpcServer := grpc.NewServer()
	chatServer := NewChatServer()

	chatpb.RegisterChatServiceServer(grpcServer, chatServer)

	log.Println("Сервер запущен на порту :6472")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Не удалось запустить сервер: %v", err)
	}
}
