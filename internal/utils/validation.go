package utils

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

// ValidatorTagFunc is a helper function to extract the field name from the json tag
// of a struct field
func ValidatorTagFunc(fld reflect.StructField) string {
	field := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
	if field == "-" {
		return ""
	}

	return field
}

// ProcessValidationErrors is a function that processes validation errors
// and returns a slice of API errors
func ProcessValidationErrors(err error) []fiber.Map {
	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		var errors []fiber.Map
		for _, e := range ve {
			errors = append(errors, fiber.Map{
				"field": e.Field(),
				"error": fmt.Sprintf("%s %s", e.Field(), processTag(e.Tag(), e.Param())),
			})
		}
		return errors
	}
	return nil

}

// processTag is a function that processes a tag and returns a string
// with the processed tag
func processTag(tag string, otherInfo ...string) string {
	switch tag {
	case "required":
		return "is required"
	case "email":
		return "should be a valid email address"
	case "min":
		return fmt.Sprintf("should be at least %s characters long", otherInfo[0])
	case "alpha":
		return "should contain only alphabetic characters"
	case "alphanum":
		return "should contain only alphanumeric characters"
	default:
		return "is invalid"
	}
}
