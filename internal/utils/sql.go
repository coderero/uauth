package utils

import (
	"errors"
	"fmt"
	"strings"

	"github.com/coderero/paas-project/internal/types"
)

const (
	defaultPage  = 1
	defaultLimit = 10
	maxLimit     = 50
)

var (
	ErrFillterOverflow = errors.New("cannot apply more than 3 filters")
)

// BuildUserAccessSQL builds the SQL query for the user access filter.
func BuildUserAccessSQL(filter *types.UserAccessFilter) (string, error) {
	var conditions []string
	filterCount := 0
	baseQuery := "SELECT * FROM auth_users"

	// Handle 'Every' flag separately
	if filter.Every {
		if filter.Admin != "" && filter.Admin == "true" {
			conditions = append(conditions, "is_admin = true OR is_admin = false")
			filterCount++
		} else {
			conditions = append(conditions, "is_admin = false")
			filterCount++
		}
		if filter.Superadmin != "" && filter.Superadmin == "true" {
			conditions = append(conditions, "is_superadmin = true OR is_superadmin = false")
			filterCount++
		} else {
			conditions = append(conditions, "is_superadmin = false")
			filterCount++
		}
		whereClause := strings.Join(conditions, " AND ")
		baseQuery = fmt.Sprintf("%s WHERE %s", baseQuery, whereClause)
		return baseQuery, nil
	}

	filters := map[string]string{
		"Active":     getConditions("is_active", filter.Active),
		"Deleted":    getConditions("deleted_at", filter.Deleted),
		"Admin":      getConditions("is_admin", filter.Admin),
		"Superadmin": getConditions("is_superadmin", filter.Superadmin),
	}

	for _, v := range filters {
		if v != "" {
			conditions = append(conditions, v)
			filterCount++
		} else {
			continue
		}
	}

	// Build the final SQL query based on the filters
	whereClause := strings.Join(conditions, " AND ")

	// Add WHERE clause if there are any conditions
	if whereClause != "" {
		baseQuery = fmt.Sprintf("%s WHERE %s", baseQuery, whereClause)
	}

	// Add pagination (LIMIT and OFFSET), if provided
	if filter.Page == 0 {
		filter.Page = defaultPage
	}

	if filter.Limit == 0 {
		filter.Limit = defaultLimit
	}

	if filter.Limit > maxLimit {
		filter.Limit = maxLimit
	}

	orderField, order := SortPatternParser(filter.SortBy, filter.Order)
	offset := (filter.Page - 1) * filter.Limit
	baseQuery = fmt.Sprintf("%s ORDER BY %s %s LIMIT %d OFFSET %d", baseQuery, orderField, order, filter.Limit, offset)
	return baseQuery, nil
}

// getConditions for the boolean fields
func getConditions(field, value string) string {
	switch value {
	case "true":
		return fmt.Sprintf("%s = true", field)
	case "false":
		return fmt.Sprintf("%s = false", field)
	default:
		return ""
	}
}

// Sort Pattern parser for the sort_by and order fields in the filter if the
// requested field is not allowed it will return the default sort field and order
// if the order is not "asc" or "desc" it will return the default order to
// prevent SQL injection
func SortPatternParser(sortBy, order string) (string, string) {
	allowedFields := map[string]bool{
		"created_at": true,
		"updated_at": true,
		"email":      true,
		"username":   true,
	}

	if !allowedFields[sortBy] {
		return "created_at", "desc"
	}

	if order != "asc" && order != "desc" {
		return sortBy, "desc"
	}

	return sortBy, order
}
