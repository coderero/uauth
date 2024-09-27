package handlers

import (
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

type userUpdateRequest struct {
	FirstName string `json:"first_name" `
	LastName  string `json:"last_name" `
	Username  string `json:"username" `
	Email     string `json:"email" validate:"omitempty,email" `
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

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "admin" && role != "superadmin" {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "forbidden",
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

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "admin" && role != "superadmin" {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "forbidden",
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

	currentUser, err := u.userService.GetByEmail(sub)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}
	role := currentUser.GetRole()

	if role != "admin" && role != "superadmin" {
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "forbidden",
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

	return ctx.JSON(safeUsers)
}

// Update updates a user but only can be used by admin or superadmin.
func (u *UserHandler) Update(ctx *fiber.Ctx) error {
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
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "forbidden",
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

	user, err := u.userService.GetByID(id)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "user not found")
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
func (u *UserHandler) SoftDelete(ctx *fiber.Ctx) error {
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
		return ctx.Status(fiber.StatusForbidden).JSON(types.APIResponse{
			Status:  fiber.StatusForbidden,
			Message: "forbidden",
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
func (u *UserHandler) HardDelete(ctx *fiber.Ctx) error {
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
