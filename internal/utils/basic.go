package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// BinarySearch is a function that searches for a value in a sorted slice
// and returns true if the value is found, otherwise false
// The time complexity of this function is O(log n)
func BinarySearch(slice []string, target string) int {
	low := 0
	high := len(slice) - 1

	for low <= high {
		mid := low + (high-low)/2
		if slice[mid] == target {
			return mid
		} else if slice[mid] < target {
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	return -1
}

// ExtractInformation is a function that extracts information from an error message
// and returns a string with the extracted information or the error message
func ProcessError(err error) fiber.Map {
	errMsg := fmt.Sprintf("%s ", err)
	castringError := regexp.MustCompile(`cannot unmarshal (.*?) into Go struct field (.*?) of type (.*?) `)

	if castringError.MatchString(errMsg) {
		field := strings.Split(castringError.FindStringSubmatch(errMsg)[2], ".")[1]
		givenType := castringError.FindStringSubmatch(errMsg)[1]
		expectedType := castringError.FindStringSubmatch(errMsg)[3]
		return fiber.Map{
			"field": field,
			"error": fmt.Sprintf("should be of type %s, got %s", expectedType, givenType),
		}

	}

	return fiber.Map{
		"error": errMsg,
	}
}

// BoolToString is a function that converts a boolean value to a string
func BoolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ParseURLValue is a function that parses the URL values and returns the the string value
func ParseURLValue(value string) (string, error) {
	value, err := url.QueryUnescape(value)
	if err != nil {
		return "", err
	}
	return value, nil
}
