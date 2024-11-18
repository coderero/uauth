package middlewares

import (
	"errors"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/coderero/paas-project/internal/cache"
	"github.com/coderero/paas-project/internal/services"
	"github.com/coderero/paas-project/internal/types"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/sync/errgroup"
)

type authType int

const (
	headerAuth authType = iota
	cookieAuth
)

var (
	// errInvalidHeader is the error returned when the header is invalid.
	errInvalidHeader = errors.New("invalid header")
)

type AuthMiddleware interface {
	// AuthMiddleware is a middleware that checks if the user is authenticated.
	AuthMiddleware(*fiber.Ctx) error

	// AuthRouteMiddleware is a middleware that checks if the user is authenticated then returns response already logged in.
	AuthRouteMiddleware(*fiber.Ctx) error
}

type tokenConfig struct {
	AccessTokenValid  bool
	RefreshTokenValid bool
	AccessToken       string
	RefreshToken      string
	Sub               string
	AuthType          authType
}

// authMiddleware is the implementation of the AuthMiddleware interface.
type authMiddleware struct {
	jwtService services.JwtService
	userCache  cache.UserCache
}

// NewAuthMiddleware creates a new auth middleware.
func NewAuthMiddleware(jwtService services.JwtService, userCache cache.UserCache) AuthMiddleware {
	return &authMiddleware{
		jwtService: jwtService,
		userCache:  userCache,
	}
}

func (a *authMiddleware) AuthMiddleware(c *fiber.Ctx) error {
	if c.Path() == "/api/v1/csrf" {
		log.Print("csrf")
		return c.Next()
	}

	tokenConfig, err := a.areTokensValid(c)
	if err != nil {
		if errors.Is(err, errInvalidHeader) {
			return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusUnauthorized,
				Message: "unauthorized",
				Details: fiber.Map{
					"error": "invalid token header",
				},
			})
		} else {
			log.Print(err)
			return c.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
				Status:  fiber.StatusInternalServerError,
				Message: "internal server error",
				Details: fiber.Map{
					"error": "something went wrong",
				},
			})
		}
	}

	if !tokenConfig.AccessTokenValid && !tokenConfig.RefreshTokenValid {
		return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	if !tokenConfig.AccessTokenValid && tokenConfig.RefreshTokenValid {
		claims, err := a.jwtService.GetClaims(tokenConfig.RefreshToken)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusUnauthorized,
				Message: "unauthorized",
			})
		}

		sub, ok := (*claims)["sub"].(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusUnauthorized,
				Message: "unauthorized",
			})
		}

		role, ok := (*claims)["role"].(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusUnauthorized,
				Message: "unauthorized",
			})
		}

		newAccessToken, err := a.jwtService.GenerateToken(&types.TokenConfig{
			Sub:  sub,
			Role: role,
			Typ:  types.AccessToken,
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
				Status:  fiber.StatusInternalServerError,
				Message: "internal server error",
				Details: fiber.Map{
					"error": "something went wrong",
				},
			})
		}

		if tokenConfig.AuthType == cookieAuth {
			c.Cookie(&fiber.Cookie{
				Name:     "__Secure_a_token",
				Value:    newAccessToken,
				Expires:  time.Now().Add(time.Hour * 24),
				Secure:   true,
				HTTPOnly: true,
				SameSite: "Strict",
			})
		} else {
			c.Set("Authorization", "Bearer "+newAccessToken)
		}

		c.Locals("user", sub)
		return c.Next()
	}

	claims, err := a.jwtService.GetClaims(tokenConfig.AccessToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	sub, ok := (*claims)["sub"].(string)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	// Check if the user is active or not
	isPresent, err := a.userCache.GetInactiveUser(sub)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "internal server error",
		})
	}

	if isPresent {
		return c.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "user has not verified email",
		})
	}

	c.Locals("user", sub)
	return c.Next()
}

func (a *authMiddleware) AuthRouteMiddleware(c *fiber.Ctx) error {
	tokenConfig, err := a.areTokensValid(c)
	if err != nil {
		if errors.Is(err, errInvalidHeader) {
			return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusUnauthorized,
				Message: "unauthorized",
				Details: fiber.Map{
					"error": "invalid token header",
				},
			})
		} else {
			return c.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
				Status:  fiber.StatusInternalServerError,
				Message: "internal server error",
				Details: fiber.Map{
					"error": "something went wrong",
				},
			})
		}
	}

	path := c.Path()
	if !tokenConfig.AccessTokenValid && !tokenConfig.RefreshTokenValid {
		//find a way to check if the path is a reset password route has a token
		if path == "/auth/v1/login" || path == "/auth/v1/register" || path == "/auth/v1/reset-password" || regexp.MustCompile("/auth/v1/reset-password/.*").MatchString(path) {
			return c.Next()
		} else {
			return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusUnauthorized,
				Message: "unauthorized",
				Details: fiber.Map{
					"error": "not logged in",
				},
			})
		}
	}

	if tokenConfig.AccessTokenValid || tokenConfig.RefreshTokenValid {
		if path == "/auth/v1/login" || path == "/auth/v1/register" {
			return c.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusBadRequest,
				Message: "bad request",
				Details: fiber.Map{
					"error": "already logged in",
				},
			})
		} else {
			return c.Next()
		}
	}

	return c.Next()
}

func (a *authMiddleware) areTokensValid(c *fiber.Ctx) (*tokenConfig, error) {
	var (
		accessToken, refreshToken string
		at                        authType
		err                       error
	)

	accessToken = c.Cookies("__Secure_a_token")
	refreshToken = c.Cookies("__Secure_r_token")

	if accessToken == "" && refreshToken == "" {
		at = headerAuth
		authHeader := strings.Split(c.Get("Authorization"), "Bearer ")
		if len(authHeader) <= 1 {
			accessToken = ""
		} else if len(authHeader) != 2 && authHeader[0] != "Bearer " {
			return nil, errInvalidHeader
		} else {
			accessToken = authHeader[1]
		}

		refreshToken = c.Get("x-refresh-token")

		if accessToken == "" && refreshToken == "" {
			return &tokenConfig{
				AccessTokenValid:  false,
				RefreshTokenValid: false,
				AccessToken:       accessToken,
				RefreshToken:      refreshToken,
				AuthType:          at,
			}, nil
		}
	} else {
		at = cookieAuth
	}

	g, _ := errgroup.WithContext(c.Context())

	var accessValid, refreshValid bool

	g.Go(func() error {
		var err error
		accessValid, err = a.jwtService.IsValidToken(accessToken, types.AccessToken)
		return err
	})

	g.Go(func() error {
		var err error
		refreshValid, err = a.jwtService.IsValidToken(refreshToken, types.RefreshToken)
		return err
	})

	if err = g.Wait(); err != nil {
		return nil, err
	}

	// Get the sub from the refresh token
	claims, err := a.jwtService.GetClaims(refreshToken)
	if err != nil {
		return nil, err
	}

	sub, ok := (*claims)["sub"].(string)
	if !ok {
		return nil, errors.New("invalid sub")
	}

	c.Locals("user", sub)

	return &tokenConfig{
		AccessTokenValid:  accessValid,
		RefreshTokenValid: refreshValid,
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		AuthType:          at,
	}, nil
}
