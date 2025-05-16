package middleware

import (
	"api-gateway/internal/auth"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
)

const (
	ContextKeySubClaim = "sub_claim"
)

func JWTAuthMiddleware() fiber.Handler {
	cognitoConfig := auth.NewCognitoConfig()

	return func(c *fiber.Ctx) error {
		// OPTIONS 메서드는 인증 없이 통과
		if c.Method() == fiber.MethodOptions {
			return c.Next()
		}

		// Swagger UI 접근 허용 설정이 활성화된 경우
		if os.Getenv("ENABLE_SWAGGER_PASS") == "true" {
			path := c.Path()
			if strings.HasPrefix(path, "/docs") || path == "/openapi.json" {
				return c.Next()
			}
		}

		// Authorization 헤더 확인
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "missing authorization header")
		}

		// Bearer 토큰 형식 확인
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid authorization header format")
		}

		token := parts[1]
		if token == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid token")
		}

		// Cognito JWT 토큰 검증
		claims, err := cognitoConfig.ValidateToken(token)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid token")
		}

		// sub 클레임을 컨텍스트에 저장
		c.Locals(ContextKeySubClaim, claims.Sub)

		return c.Next()
	}
}
