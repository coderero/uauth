package handlers

import (
	"errors"

	"github.com/coderero/paas-project/api/models"
	"github.com/coderero/paas-project/internal/services"
	"github.com/coderero/paas-project/internal/types"
	"github.com/coderero/paas-project/internal/utils"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type safeUserResponse struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	Email     string `json:"email"`
}

type createUserRequest struct {
	registerRequest
	IsAdmin      bool `json:"is_admin"`
	IsActive     bool `json:"is_active"`
	IsSuperadmin bool `json:"is_superadmin"`
}

type userUpdateRequest struct {
	FirstName string `json:"first_name" `
	LastName  string `json:"last_name" `
	Username  string `json:"username" `
	Email     string `json:"email" validate:"omitempty,email" `
}

type adminUpdateUserRequest struct {
	userUpdateRequest
	IsAdmin      bool `json:"is_admin"`
	IsActive     bool `json:"is_active"`
	IsSuperadmin bool `json:"is_superadmin"`
}

type deleteSelfRequest struct {
	Confirm bool `json:"confirm" validate:"required"`
}

type UserHandler struct {
	validator   *validator.Validate
	userService services.UserService
}

func NewUserHandler(v *validator.Validate, us services.UserService) *UserHandler {
	return &UserHandler{
		validator:   v,
		userService: us,
	}
}

// CreateUser creates a new user but only can be used by admin or superadmin.
func (u *UserHandler) CreateUser(ctx *fiber.Ctx) error {
	var req createUserRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessError(err),
		})
	}

	if err := u.validator.Struct(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessValidationErrors(err),
		})
	}

	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	if currentUser.GetRole() != "admin" && currentUser.GetRole() != "superadmin" {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "forbidden",
		})
	}
	user := &models.User{
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Username:     req.Username,
		Email:        req.Email,
		Password:     req.Password,
		IsAdmin:      req.IsAdmin,
		IsActive:     req.IsActive,
		IsSuperadmin: req.IsSuperadmin,
	}

	id, err := u.userService.Create(user)
	if err != nil {
		if errors.Is(err, services.ErrUserAlreadyExists) {
			return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
				Status:  fiber.StatusBadRequest,
				Message: "user already exists",
			})
		}

		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong",
		})
	}

	return ctx.JSON(types.APIResponse{
		Status:  fiber.StatusCreated,
		Message: "user created",
		Details: fiber.Map{
			"id": id,
		},
	})
}

// GetUserByID returns a user by its ID.
func (u *UserHandler) GetUserByID(ctx *fiber.Ctx) error {
	id, err := ctx.ParamsInt("id")
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "invalid user id",
		})
	}

	user, err := u.userService.GetByID(id)
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
			Status:  fiber.StatusNotFound,
			Message: "user not found",
		})
	}

	safeUser := safeUserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Username:  user.Username,
		Email:     user.Email,
	}

	return ctx.JSON(safeUser)
}

// GetUserByUsername returns a user by its username.
func (u *UserHandler) GetUserByUsername(ctx *fiber.Ctx) error {
	username := ctx.Params("username")

	user, err := u.userService.GetByUsername(username)
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
			Status:  fiber.StatusNotFound,
			Message: "user not found",
		})
	}

	safeUser := safeUserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Username:  user.Username,
		Email:     user.Email,
	}

	return ctx.JSON(safeUser)
}

// GetUserByEmail returns a user by its email.
func (u *UserHandler) GetUserByEmail(ctx *fiber.Ctx) error {
	email := ctx.Params("email")

	user, err := u.userService.GetByEmail(email)
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
			Status:  fiber.StatusNotFound,
			Message: "user not found",
		})
	}

	safeUser := safeUserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Username:  user.Username,
		Email:     user.Email,
	}

	return ctx.JSON(safeUser)
}

// GetAllActive returns all active users.
func (u *UserHandler) GetAllActive(ctx *fiber.Ctx) error {
	page := ctx.QueryInt("page")
	limit := ctx.QueryInt("limit")

	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	if page < 1 || limit < 10 {
		page = 1
		limit = 10
	}

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "admin" && role != "superadmin" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	users, err := u.userService.GetAllActive(role, page, limit)
	if err != nil {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "invalid permission",
		})
	}

	var safeUsers []safeUserResponse
	for _, user := range users {
		safeUser := safeUserResponse{
			ID:        user.ID,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Username:  user.Username,
			Email:     user.Email,
		}
		safeUsers = append(safeUsers, safeUser)
	}

	return ctx.JSON(safeUsers)
}

// GetAllInactive returns all inactive users.
func (u *UserHandler) GetAllInactive(ctx *fiber.Ctx) error {
	page := ctx.QueryInt("page")
	limit := ctx.QueryInt("limit")

	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	if page < 1 || limit < 10 {
		page = 1
		limit = 10
	}

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "admin" && role != "superadmin" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	users, err := u.userService.GetAllInactive(role, page, limit)
	if err != nil {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "invalid permission",
		})
	}

	var safeUsers []safeUserResponse
	for _, user := range users {
		safeUser := safeUserResponse{
			ID:        user.ID,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Username:  user.Username,
			Email:     user.Email,
		}
		safeUsers = append(safeUsers, safeUser)
	}

	return ctx.JSON(safeUsers)
}

func (u *UserHandler) GetAllDeleted(ctx *fiber.Ctx) error {
	page := ctx.QueryInt("page")
	limit := ctx.QueryInt("limit")

	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	if page < 1 || limit < 10 {
		page = 1
		limit = 10
	}

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "admin" && role != "superadmin" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	users, err := u.userService.GetAllDeleted(role, page, limit)
	if err != nil {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "invalid permission",
		})
	}

	var safeUsers []safeUserResponse
	for _, user := range users {
		safeUser := safeUserResponse{
			ID:        user.ID,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Username:  user.Username,
			Email:     user.Email,
		}
		safeUsers = append(safeUsers, safeUser)
	}

	return ctx.JSON(safeUsers)
}

// GetAll returns all users.
func (u *UserHandler) GetAll(ctx *fiber.Ctx) error {
	page := ctx.QueryInt("page")
	limit := ctx.QueryInt("limit")

	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	if page < 1 || limit < 10 {
		page = 1
		limit = 10
	}

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "admin" && role != "superadmin" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	users, err := u.userService.GetAll(role, page, limit)
	if err != nil {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "invalid permission",
		})
	}

	var safeUsers []safeUserResponse
	for _, user := range users {
		safeUser := safeUserResponse{
			ID:        user.ID,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Username:  user.Username,
			Email:     user.Email,
		}
		safeUsers = append(safeUsers, safeUser)
	}

	return ctx.JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "users",
		Details: safeUsers,
	})
}

// Update updates a user but only can be used by admin or superadmin.
func (u *UserHandler) UpdateUser(ctx *fiber.Ctx) error {
	id, err := ctx.ParamsInt("id")
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "invalid user id",
		})
	}

	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "admin" && role != "superadmin" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	var req adminUpdateUserRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessError(err),
		})
	}

	if err := u.validator.Struct(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessValidationErrors(err),
		})
	}

	if req.Email == "" || req.Username == "" || req.FirstName == "" || req.LastName == "" || !req.IsAdmin || !req.IsActive || !req.IsSuperadmin {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "any one of the fields is required",
		})
	}

	user, err := u.userService.GetByID(id)
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
			Status:  fiber.StatusNotFound,
			Message: "user not found",
		})
	}

	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.Username = req.Username
	user.Email = req.Email

	if err := u.userService.Update(user); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong",
		})
	}

	return ctx.JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "user updated",
	})
}

// UpdateSelf updates the current user.
func (u *UserHandler) UpdateSelf(ctx *fiber.Ctx) error {
	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	var req userUpdateRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessError(err),
		})
	}

	if err := u.validator.Struct(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessValidationErrors(err),
		})
	}

	if req.Email == "" || req.Username == "" || req.FirstName == "" || req.LastName == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "any one of the fields is required",
		})
	}

	user, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
			Status:  fiber.StatusNotFound,
			Message: "user not found",
		})
	}

	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.Username = req.Username
	user.Email = req.Email

	if err := u.userService.Update(user); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong",
		})
	}

	return ctx.JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "user updated",
	})
}

// SoftDelete soft deletes a user but only can be used by admin or superadmin.
func (u *UserHandler) SoftDeleteUser(ctx *fiber.Ctx) error {
	id, err := ctx.ParamsInt("id")
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "invalid user id",
		})
	}

	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "admin" && role != "superadmin" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	if err := u.userService.SoftDelete(id); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong",
		})
	}

	return ctx.JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "user soft deleted",
	})
}

// SoftDeleteSelf soft deletes the current user.
func (u *UserHandler) SoftDeleteSelf(ctx *fiber.Ctx) error {
	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	var req deleteSelfRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessError(err),
		})
	}

	if err := u.validator.Struct(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessValidationErrors(err),
		})
	}

	if !req.Confirm {
		return ctx.JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "confirm field is required",
		})
	}

	user, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
			Status:  fiber.StatusNotFound,
			Message: "user not found",
		})
	}

	if err := u.userService.SoftDelete(user.ID); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong",
		})
	}

	ctx.ClearCookie("__Secure_a_token")
	ctx.ClearCookie("__Secure_r_token")

	return ctx.JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "user soft deleted",
	})
}

// HardDelete hard deletes a user but only can be used by superadmin.
func (u *UserHandler) HardDeleteUser(ctx *fiber.Ctx) error {
	id, err := ctx.ParamsInt("id")
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "invalid user id",
		})
	}

	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "superadmin" {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "forbidden",
		})
	}

	if err := u.userService.HardDelete(id); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong",
		})
	}

	return ctx.JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "user hard deleted",
	})
}
