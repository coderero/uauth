package models

type Project struct {
	ID           int    `json:"id"`
	Title        string `json:"title"`
	Deadline     any    `json:"deadline"`
	UserID       int    `json:"user_id"`
	Description  string `json:"description"`
	PermissionID int    `json:"permission_id"`
	CreatedAt    any    `json:"created_at"`
	UpdatedAt    any    `json:"updated_at"`
	DeletedAt    any    `json:"deleted_at"`
}

type ProjectUser struct {
	ID        int    `json:"id"`
	ProjectID int    `json:"project_id"`
	UserID    int    `json:"user_id"`
	Role      string `json:"role"`
	CreatedAt any    `json:"created_at"`
	UpdatedAt any    `json:"updated_at"`
}

type ProjectTask struct {
	ID          int    `json:"id"`
	ProjectID   int    `json:"project_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Logo        string `json:"logo"`
	Banner      string `json:"banner"`
	Deadline    any    `json:"deadline"`
	IsDone      bool   `json:"is_done"`
	CreatedAt   any    `json:"created_at"`
	UpdatedAt   any    `json:"updated_at"`
}

type ProjectTaskUser struct {
	ID         int `json:"id"`
	TaskID     int `json:"task_id"`
	UserID     int `json:"user_id"`
	Permission int `json:"permission"`
	CreatedAt  any `json:"created_at"`
	UpdatedAt  any `json:"updated_at"`
}

type ProjectTaskComment struct {
	ID                      int    `json:"id"`
	PermmissionAssignmentID int    `json:"permmission_assignment_id"`
	UserID                  int    `json:"user_id"`
	Comment                 string `json:"comment"`
	Attachment              string `json:"attachment"`
	CreatedAt               any    `json:"created_at"`
	UpdatedAt               any    `json:"updated_at"`
}

type ProjectRoles struct {
	ID          int    `json:"id"`
	ProjectID   int    `json:"project_id"`
	Title       string `json:"title"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	CreatedBy   int    `json:"created_by"`
	IsActive    bool   `json:"is_active"`
	CreatedAt   any    `json:"created_at"`
	UpdatedAt   any    `json:"updated_at"`
}

type ProjectRolePermission struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	CreatedBy   int    `json:"created_by"`
	UserId      int    `json:"user_id"`
	RoleId      int    `json:"role_id"`
	CreatedAt   any    `json:"created_at"`
	UpdatedAt   any    `json:"updated_at"`
}
