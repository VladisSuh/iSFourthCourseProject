package grpcclient

import (
	"log"

	"google.golang.org/grpc"
	chatpb "iSFourthCourseProject/proto/chatpb"
)

var (
	ChatClient chatpb.ChatServiceClient
	grpcConn   *grpc.ClientConn
)

func InitGRPCClient() {
	conn, err := grpc.Dial("localhost:6472", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Не удалось подключиться к gRPC-серверу: %v", err)
	}
	ChatClient = chatpb.NewChatServiceClient(conn)
}

// CloseGRPC закрывает соединение с gRPC-сервером
func CloseGRPC() {
	if grpcConn != nil {
		if err := grpcConn.Close(); err != nil {
			log.Printf("Ошибка при закрытии gRPC-соединения: %v", err)
		}
	}
}
