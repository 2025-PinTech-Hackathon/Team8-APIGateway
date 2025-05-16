package main

import (
	"api-gateway/internal/handler"
	"api-gateway/internal/middleware"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/joho/godotenv"
)

func main() {
	// dotenv 파일 로드 (Production 환경이 아닌 경우)
	if os.Getenv("ENV") != "prod" {
		err := godotenv.Load()
		if err != nil {
			log.Fatalf("Error loading .env file: %v", err)
		}
	}

	// Fiber 앱 생성
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	// CORS 미들웨어 설정
	app.Use(cors.New(cors.Config{
		AllowOrigins:     os.Getenv("ALLOW_ORIGINS"),
		AllowMethods:     "GET,POST,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))

	// 로깅 미들웨어 설정
	app.Use(logger.New())

	// Health check 엔드포인트
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(200).JSON(fiber.Map{
			"status": "ok",
		})
	})

	// JWT 인증 미들웨어 설정
	app.Use(middleware.JWTAuthMiddleware())

	// 모든 경로에 대해 프록시 핸들러 설정
	app.All("/*", handler.ProxyHandler())

	// 서버 포트 설정
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "3000"
	}

	// 서버 시작
	log.Printf("API Gateway starting on port %s\n", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Error starting server: %v\n", err)
	}
}
