package models

import (
	"net"

	"github.com/coderero/paas-project/internal/types"
)

// User represents a user in the system.
type User struct {
	ID           int            `json:"id"`
	FirstName    string         `json:"first_name"`
	LastName     string         `json:"last_name"`
	Username     string         `json:"username"`
	Email        string         `json:"email"`
	Password     string         `json:"password"`
	IsVerified   bool           `json:"is_verified"`
	IsSuperadmin bool           `json:"is_superadmin"`
	IsAdmin      bool           `json:"is_admin"`
	IsActive     bool           `json:"is_active"`
	CreatedAt    types.NullTime `json:"created_at"`
	UpdatedAt    types.NullTime `json:"updated_at"`
	DeletedAt    types.NullTime `json:"deleted_at"`
}

func (u *User) GetRole() string {
	switch {
	case u.IsSuperadmin:
		return "superadmin"
	case u.IsAdmin:
		return "admin"
	default:
		return "user"
	}
}

// UsedPassword represents a used password.
type UsedPassword struct {
	ID        int    `json:"id"`
	UserID    int    `json:"user_id"`
	Password  string `json:"password"`
	CreatedAt string `json:"created_at"`
}

// AuthLog represents an authentication log.
type AuthLog struct {
	ID        int    `json:"id"`
	UserID    int    `json:"user_id"`
	IPAddress net.IP `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	CreatedAt string `json:"created_at"`
}
