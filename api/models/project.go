package models

import "github.com/coderero/paas-project/internal/types"

type Project struct {
	ID           int            `json:"id"`
	Title        string         `json:"title"`
	Deadline     types.NullTime `json:"deadline"`
	UserID       int            `json:"user_id"`
	Description  string         `json:"description"`
	PermissionID int            `json:"permission_id"`
	CreatedAt    types.NullTime `json:"created_at"`
	UpdatedAt    types.NullTime `json:"updated_at"`
	DeletedAt    types.NullTime `json:"deleted_at"`
}

type ProjectUser struct {
	ID        int            `json:"id"`
	ProjectID int            `json:"project_id"`
	UserID    int            `json:"user_id"`
	Role      string         `json:"role"`
	CreatedAt types.NullTime `json:"created_at"`
	UpdatedAt types.NullTime `json:"updated_at"`
}

type ProjectTask struct {
	ID          int            `json:"id"`
	ProjectID   int            `json:"project_id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Logo        string         `json:"logo"`
	Banner      string         `json:"banner"`
	Deadline    types.NullTime `json:"deadline"`
	IsDone      bool           `json:"is_done"`
	CreatedAt   types.NullTime `json:"created_at"`
	UpdatedAt   types.NullTime `json:"updated_at"`
}

type ProjectTaskUser struct {
	ID         int            `json:"id"`
	TaskID     int            `json:"task_id"`
	UserID     int            `json:"user_id"`
	Permission int            `json:"permission"`
	CreatedAt  types.NullTime `json:"created_at"`
	UpdatedAt  types.NullTime `json:"updated_at"`
}

type ProjectTaskComment struct {
	ID                      int            `json:"id"`
	PermmissionAssignmentID int            `json:"permmission_assignment_id"`
	UserID                  int            `json:"user_id"`
	Comment                 string         `json:"comment"`
	Attachment              string         `json:"attachment"`
	CreatedAt               types.NullTime `json:"created_at"`
	UpdatedAt               types.NullTime `json:"updated_at"`
}

type ProjectRoles struct {
	ID          int            `json:"id"`
	ProjectID   int            `json:"project_id"`
	Title       string         `json:"title"`
	Slug        string         `json:"slug"`
	Description string         `json:"description"`
	CreatedBy   int            `json:"created_by"`
	IsActive    bool           `json:"is_active"`
	CreatedAt   types.NullTime `json:"created_at"`
	UpdatedAt   types.NullTime `json:"updated_at"`
}

type ProjectRolePermission struct {
	ID          int            `json:"id"`
	Title       string         `json:"title"`
	Slug        string         `json:"slug"`
	Description string         `json:"description"`
	CreatedBy   int            `json:"created_by"`
	UserId      int            `json:"user_id"`
	RoleId      int            `json:"role_id"`
	CreatedAt   types.NullTime `json:"created_at"`
	UpdatedAt   types.NullTime `json:"updated_at"`
}
