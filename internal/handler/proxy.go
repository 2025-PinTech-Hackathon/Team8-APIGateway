package handler

import (
	"api-gateway/internal/middleware"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/proxy"
)

func ProxyHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		targetURL := os.Getenv("TARGET_ENDPOINT")
		if targetURL == "" {
			return fiber.NewError(fiber.StatusInternalServerError, "target endpoint not configured")
		}

		// 원본 요청 URL의 path와 query string을 유지
		url := targetURL + c.OriginalURL()

		// sub 클레임을 X-AUTH-SUB 헤더에 추가
		if sub, ok := c.Locals(middleware.ContextKeySubClaim).(string); ok {
			c.Request().Header.Set("X-AUTH-SUB", sub)
		}

		// 프록시 요청 설정
		if err := proxy.Do(c, url); err != nil {
			return fiber.NewError(fiber.StatusBadGateway, "proxy request failed")
		}

		// 응답 헤더 설정
		c.Response().Header.Del(fiber.HeaderServer)

		return nil
	}
}
