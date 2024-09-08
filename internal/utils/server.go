package utils

import (
	"errors"

	"github.com/coderero/paas-project/internal/types"
	"github.com/gofiber/fiber/v2"
)

// ErrorHandler is a function that handles errors
func ErrorHandler(ctx *fiber.Ctx, err error) error {
	// Status code defaults to 500
	code := fiber.StatusInternalServerError

	// Retrieve the custom status code if it's a *fiber.Error
	var e *fiber.Error
	if errors.As(err, &e) {
		code = e.Code
	}

	// Send error message
	return ctx.Status(code).JSON(types.APIResponse{
		Status:  e.Code,
		Message: processCodeToMessage(code),
	})
}

func processCodeToMessage(code int) string {
	switch code {
	case fiber.StatusBadRequest:
		return "bad request"
	case fiber.StatusUnauthorized:
		return "unauthorized"
	case fiber.StatusForbidden:
		return "forbidden"
	case fiber.StatusNotFound:
		return "not found"
	case fiber.StatusMethodNotAllowed:
		return "method not allowed"
	case fiber.StatusNotAcceptable:
		return "not acceptable"
	case fiber.StatusConflict:
		return "conflict in request"
	case fiber.StatusTooManyRequests:
		return "too many requests"
	case fiber.StatusInternalServerError:
		return "internal server error"
	case fiber.StatusServiceUnavailable:
		return "service unavailable"
	default:
		return "unknown error"
	}
}
