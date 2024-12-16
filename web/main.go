package main

import (
	"iSFourthCourseProject/web/grpcclient"
	"iSFourthCourseProject/web/middleware"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"iSFourthCourseProject/web/handlers"
)

func main() {
	grpcclient.InitGRPCClient()
	defer grpcclient.CloseGRPC()
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		dsn = "postgres://user1:password@localhost:5432/mydb1?sslmode=disable"
	}

	if err := handlers.InitializeDB(dsn); err != nil {
		log.Fatalf("Не удалось инициализировать БД: %v", err)
	}

	router := gin.Default()

	// Загрузка HTML-шаблонов
	router.LoadHTMLGlob("templates/*")

	// Обслуживание статических файлов
	router.Static("/static", "./static")

	// Главная страница
	router.GET("/", func(c *gin.Context) {
		c.HTML(200, "home.html", nil)
	})

	// Маршруты для авторизации
	router.GET("/register", func(c *gin.Context) {
		c.HTML(200, "register.html", nil)
	})
	router.POST("/register", handlers.Register)

	router.GET("/login", func(c *gin.Context) {
		c.HTML(200, "login.html", nil)
	})
	router.POST("/login", handlers.Login)

	// Группа маршрутов, требующих авторизации
	authorized := router.Group("/chats")
	authorized.Use(middleware.AuthMiddleware())
	{
		// Маршрут для меню чатов
		authorized.GET("/menu", handlers.MenuHandler)

		// Маршрут для отображения страницы чата с room_id
		authorized.GET("/chat", handlers.ChatHandler) // /chats/chat?room_id=...

		// Маршрут для отображения страницы создания чата (GET)
		authorized.GET("/create_chat", handlers.ShowCreateChatPage)

		// Маршрут для обработки создания чата (POST)
		authorized.POST("/create_chat", handlers.CreateChat)

		// Маршрут для присоединения к чату (POST)
		authorized.POST("/join_chat", handlers.JoinChat)

		// WebSocket маршрут
		authorized.GET("/ws", handlers.WebSocketHandler)

		// Маршрут для отправки приглашения (POST)
		authorized.POST("/send_invitation", handlers.SendInvitationHandler)

		// Маршрут для получения списка приглашений (GET)
		authorized.GET("/invitations", handlers.ListInvitationsHandler)

		// Маршрут для ответа на приглашение (POST)
		authorized.POST("/respond_invitation", handlers.RespondInvitationHandler)

		// Маршрут для отправки файла
		authorized.POST("/chat/send-file", handlers.SendFileHandler)
		authorized.GET("/chat/files", handlers.ListFilesHandler)
		authorized.GET("/chat/download-file", handlers.DownloadFileHandler)

		// Маршрут для удаления чата
		authorized.DELETE("/chat", handlers.DeleteChatHandler)

		// Маршрут для выхода из профиля
		authorized.GET("/logout", handlers.LogoutHandler)
	}

	// Запуск сервера на порту 6492
	if err := router.Run(":6492"); err != nil {
		log.Fatalf("Не удалось запустить сервер: %v", err)
	}
}
