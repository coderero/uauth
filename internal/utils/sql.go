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
		if filter.Admin {
			conditions = append(conditions, "is_admin = true OR is_admin = false")
			filterCount++
		} else {
			conditions = append(conditions, "is_admin = false")
			filterCount++
		}
		if filter.Superadmin {
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

	// Track the number of filters applied and ensure it's within the limit
	if filter.Active {
		conditions = append(conditions, "is_active = true")
		filterCount++
	}
	if filter.Deleted {
		conditions = append(conditions, "deleted_at IS NOT NULL")
		filterCount++
	}
	if filter.Admin {
		conditions = append(conditions, "is_admin = true")
		filterCount++
	}
	if filter.Superadmin {
		conditions = append(conditions, "is_superadmin = true")
		filterCount++
	}

	// Ensure no more than 3 filters are applied
	if filterCount > 3 {
		return "", ErrFillterOverflow
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

	offset := (filter.Page - 1) * filter.Limit
	baseQuery = fmt.Sprintf("%s ORDER BY created_at DESC LIMIT %d OFFSET %d", baseQuery, filter.Limit, offset)
	return baseQuery, nil
}
