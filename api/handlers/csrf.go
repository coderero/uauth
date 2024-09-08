package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"log"

	"github.com/coderero/paas-project/internal/cache"
	"github.com/coderero/paas-project/internal/types"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	_ "github.com/joho/godotenv/autoload"
)

const (
	empty           string = ""
	csrfTokenLength int    = 32
)

type CsrfHandler struct {
	TokenLength    int
	CsrfMiddleware func(*fiber.Ctx) error
}

func NewCsrfHandler(cache cache.Service) *CsrfHandler {
	return &CsrfHandler{
		CsrfMiddleware: csrf.New(
			csrf.Config{
				CookieName:     "__Secure_csrf",
				CookieHTTPOnly: true,
				CookieSameSite: "Lax",
				ContextKey:     "csrf",
				Expiration:     3600,

				KeyGenerator: func() string {
					b := genBytes(csrfTokenLength)
					if b == nil {
						return empty
					}
					return base64.StdEncoding.EncodeToString(b)
				},
				ErrorHandler: func(c *fiber.Ctx, err error) error {
					return c.Status(fiber.StatusForbidden).JSON(types.APIResponse{
						Status:  fiber.StatusForbidden,
						Message: "csrf token error",
					})
				},
				Extractor: func(c *fiber.Ctx) (string, error) {
					rt := c.Get("x-csrf-token")
					if rt == empty {
						return empty, csrf.ErrTokenNotFound
					}
					t, err := unmask(rt)
					if t == nil || err != nil {
						return empty, csrf.ErrTokenInvalid
					}
					token := base64.StdEncoding.EncodeToString(t)
					return token, nil
				},
			},
		),
	}
}

func (h *CsrfHandler) CSRF(ctx *fiber.Ctx) error {
	token, ok := ctx.Locals("csrf").(string)
	if !ok {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong",
		})
	}

	t := mask(token, csrfTokenLength)
	if t == empty {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong",
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "csrf token",
		Details: fiber.Map{
			"csrf": t,
		},
	})
}

// Generate random bytes for the token
func genBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil
	}
	return b
}

// XOR the two byte slices and follow the rules of the bitwise XOR operation
// https://en.wikipedia.org/wiki/Bitwise_operation#XOR
func xor(a, b []byte) []byte {
	var n int = len(a)
	if len(b) < n {
		n = len(b)
	}

	c := make([]byte, n)
	for i := 0; i < n; i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// Mask the token with random bytes and XOR the token with the random bytes
func mask(token string, length int) string {
	b := genBytes(length)
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if b == nil || err != nil {
		log.Println(err)
		return empty
	}
	b = append(b, xor(b, decodedToken)...)
	return base64.RawURLEncoding.EncodeToString(b)
}

func unmask(token string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(b) < csrfTokenLength*2 {
		log.Print(len(b))
		return nil, err
	}

	t := b[:csrfTokenLength]
	c := b[csrfTokenLength:]
	return xor(c, t), nil
}
