package handlers

import (
	"errors"
	"log"
	"time"

	"github.com/coderero/paas-project/api/models"
	"github.com/coderero/paas-project/internal/services"
	"github.com/coderero/paas-project/internal/types"
	"github.com/coderero/paas-project/internal/utils"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	validator *validator.Validate
	authSvc   services.AuthServicer
}

func NewAuthHandler(authSvc services.AuthServicer, v *validator.Validate) *AuthHandler {
	return &AuthHandler{
		validator: v,
		authSvc:   authSvc,
	}
}

type registerRequest struct {
	FirstName string `json:"first_name" validate:"required,alpha"`
	LastName  string `json:"last_name" validate:"required,alpha"`
	Username  string `json:"username" validate:"required,alphanum"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type changePassword struct {
	OldPassword     string `json:"old_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

type resetPassword struct {
	Email string `json:"email" validate:"required,email"`
}

type resetPasswordConfirm struct {
	Password        string `json:"password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

// Register registers a user with the given email and password.
func (h *AuthHandler) Register(ctx *fiber.Ctx) error {
	req := new(registerRequest)
	if err := ctx.BodyParser(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessError(err),
		})
	}

	if err := h.validator.Struct(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessValidationErrors(err),
		})
	}

	user := &models.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Username:  req.Username,
		Email:     req.Email,
		Password:  req.Password,
	}

	tokens, id, err := h.authSvc.Register(ctx.Context(), user)

	if err != nil {
		if errors.Is(err, services.ErrUserAlreadyExists) {
			return ctx.Status(fiber.StatusConflict).JSON(types.APIResponse{
				Status:  fiber.StatusConflict,
				Message: "user already exists with the given email or username",
			})
		}
		if errors.Is(err, services.ErrFailedToGenerateToken) {
			return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
				Status:  fiber.StatusInternalServerError,
				Message: "failed to generate credentials",
			})
		}

		if errors.Is(err, services.ErrFailedToSendEmail) {
			return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
				Status:  fiber.StatusInternalServerError,
				Message: "user created but failed to send verification email",
			})
		}

		if errors.Is(err, services.ErrTokenGeneration) {
			return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
				Status:  fiber.StatusInternalServerError,
				Message: "user created but failed to generate email verification token",
			})
		}

		log.Print("error: ", err)
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "something went wrong",
		})
	}

	if err := h.authSvc.CreateUsedPassword(ctx.Context(), id, user.Password); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong but user was created",
		})
	}

	if err := h.saveToken(ctx, tokens.AccessToken, types.AccessToken); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "failed to save the access token",
		})
	}

	if err := h.saveToken(ctx, tokens.RefreshToken, types.RefreshToken); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "failed to save the refresh token",
		})
	}

	if err := h.authSvc.CreateAuthLog(ctx.Context(), id, ctx.IP(), ctx.Get("User-Agent")); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong but user was created",
		})
	}

	return ctx.Status(fiber.StatusCreated).JSON(types.APIResponse{
		Status:  fiber.StatusCreated,
		Message: "successfully registered",
		Details: tokens,
	})
}

// RegenEmailVerification regenerates the email verification token for the user.
// This action is only available to authenticated users.
func (h *AuthHandler) RegenEmailVerification(ctx *fiber.Ctx) error {
	// Get the user email from the locals in the fiber
	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	err := h.authSvc.RegenEmailVerification(ctx.Context(), sub)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
				Status:  fiber.StatusNotFound,
				Message: "user not found",
			})
		} else if errors.Is(err, services.ErrFailedToSendEmail) {
			return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
				Status:  fiber.StatusInternalServerError,
				Message: "failed to send email",
			})
		}

		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "something went wrong",
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "successfully regenerated email verification token",
	})
}

// VerifyEmail verifies the email of the user.
func (h *AuthHandler) VerifyEmail(ctx *fiber.Ctx) error {
	token := ctx.Params("token")
	if token == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "payload error",
			Details: fiber.Map{
				"type":  "params",
				"error": "params not found",
			},
		})
	}

	err := h.authSvc.VerifyEmail(ctx.Context(), token)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
				Status:  fiber.StatusNotFound,
				Message: "user not found",
			})
		} else if errors.Is(err, services.ErrInvalidToken) {
			return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
				Status:  fiber.StatusBadRequest,
				Message: "invalid token",
			})
		}

		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "something went wrong",
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "successfully verified email",
	})
}

// Login logs in a user with the given email and password.
func (h *AuthHandler) Login(ctx *fiber.Ctx) error {
	req := new(loginRequest)
	if err := ctx.BodyParser(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessError(err),
		})
	}

	if err := h.validator.Struct(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessValidationErrors(err),
		})
	}

	tokens, id, err := h.authSvc.Login(ctx.Context(), req.Email, req.Password)

	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
				Status:  fiber.StatusNotFound,
				Message: "user not found",
			})
		}
		if errors.Is(err, services.ErrInvalidPassword) {
			return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusUnauthorized,
				Message: "invalid password",
			})
		}

		if errors.Is(err, services.ErrUserNotActive) {
			return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusUnauthorized,
				Message: "user not active contact the admin",
			})
		}

		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "something went wrong",
		})
	}

	if err := h.saveToken(ctx, tokens.AccessToken, types.AccessToken); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "failed to save the access token",
		})
	}

	if err := h.saveToken(ctx, tokens.RefreshToken, types.RefreshToken); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "failed to save the refresh token",
		})
	}

	if err := h.authSvc.CreateAuthLog(ctx.Context(), id, ctx.IP(), ctx.Get("User-Agent")); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "something went wrong but user was created",
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "successfully logged in",
		Details: tokens,
	})
}

func (h *AuthHandler) ChangePassword(ctx *fiber.Ctx) error {
	req := new(changePassword)
	if err := ctx.BodyParser(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessError(err),
		})
	}

	if err := h.validator.Struct(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessValidationErrors(err),
		})
	}

	if req.NewPassword == req.OldPassword {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: []fiber.Map{
				{
					"field": "new_password",
					"error": "new password should be different from the old password",
				},
			},
		})
	}

	if req.NewPassword != req.ConfirmPassword {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: []fiber.Map{
				{
					"field": "confirm_password",
					"error": "passwords do not match",
				},
			},
		})
	}

	// Get the user email from the locals in the fiber
	sub, ok := ctx.Locals("user").(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "unauthorized",
		})
	}

	err := h.authSvc.ChangePassword(ctx.Context(), sub, req.OldPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
				Status:  fiber.StatusNotFound,
				Message: "user not found",
			})
		}
		if errors.Is(err, services.ErrInvalidPassword) {
			return ctx.Status(fiber.StatusUnauthorized).JSON(types.APIResponse{
				Status:  fiber.StatusUnauthorized,
				Message: "invalid password",
			})
		}

		if errors.Is(err, services.ErrPasswordAlreadyUsed) {
			return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
				Status:  fiber.StatusBadRequest,
				Message: "password already used",
			})
		}
		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "something went wrong",
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "successfully changed password",
	})
}

func (h *AuthHandler) ResetPassword(ctx *fiber.Ctx) error {
	req := new(resetPassword)
	if err := ctx.BodyParser(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessError(err),
		})
	}

	if err := h.validator.Struct(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessValidationErrors(err),
		})
	}

	err := h.authSvc.ResetPassword(ctx.Context(), req.Email)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
				Status:  fiber.StatusNotFound,
				Message: "user not found",
			})
		} else if errors.Is(err, services.ErrFailedToSendEmail) {
			return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
				Status:  fiber.StatusInternalServerError,
				Message: "failed to send email",
			})
		}

		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "something went wrong",
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "an email has been sent to reset your password",
	})
}

func (h *AuthHandler) ResetPasswordConfirm(ctx *fiber.Ctx) error {
	token := ctx.Params("token")
	if token == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "payload error",
			Details: fiber.Map{
				"type":  "params",
				"error": "params not found",
			},
		})
	}
	req := new(resetPasswordConfirm)
	if err := ctx.BodyParser(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessError(err),
		})
	}

	if err := h.validator.Struct(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
			Status:  fiber.StatusBadRequest,
			Message: "validation error",
			Details: utils.ProcessValidationErrors(err),
		})
	}

	err := h.authSvc.VerifyAndResetPassword(ctx.Context(), token, req.Password)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			return ctx.Status(fiber.StatusNotFound).JSON(types.APIResponse{
				Status:  fiber.StatusNotFound,
				Message: "user not found",
			})
		} else if errors.Is(err, services.ErrPasswordAlreadyUsed) {
			return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
				Status:  fiber.StatusBadRequest,
				Message: "password already used",
			})
		} else if errors.Is(err, services.ErrInvalidToken) {
			return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
				Status:  fiber.StatusBadRequest,
				Message: "invalid token",
			})
		}
		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "something went wrong",
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "successfully reset password",
	})
}

func (h *AuthHandler) Logout(ctx *fiber.Ctx) error {
	var accessToken, refreshToken string
	accessToken = ctx.Cookies("__Secure_a_token")
	refreshToken = ctx.Cookies("__Secure_r_token")

	if accessToken == "" && refreshToken == "" {
		// Try to get the tokens from the request body
		req := new(types.Tokens)
		if err := ctx.BodyParser(req); err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
				Status:  fiber.StatusBadRequest,
				Message: "validation error",
				Details: utils.ProcessError(err),
			})
		}

		// Validate the request body
		if err := h.validator.Struct(req); err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(types.APIResponse{
				Status:  fiber.StatusBadRequest,
				Message: "validation error",
				Details: utils.ProcessValidationErrors(err),
			})
		}

		accessToken = req.AccessToken
		refreshToken = req.RefreshToken
	}

	if err := h.authSvc.Logout(ctx.Context(), refreshToken, accessToken); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(types.APIResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "failed to logout",
		})
	}

	ctx.ClearCookie("__Secure_a_token", "__Secure_r_token")

	return ctx.Status(fiber.StatusOK).JSON(types.APIResponse{
		Status:  fiber.StatusOK,
		Message: "successfully logged out",
	})
}

// saveTokens saves the tokens as cookies.
func (h *AuthHandler) saveToken(ctx *fiber.Ctx, token string, typ types.TokenType) error {
	var (
		name   string
		expiry time.Time
	)

	switch typ {
	case types.AccessToken:
		name = "__Secure_a_token"
		expiry = time.Now().Add(15 * time.Minute)
	case types.RefreshToken:
		name = "__Secure_r_token"
		expiry = time.Now().Add(24 * time.Hour)
	default:
		return errors.New("invalid token type")
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		Expires:  expiry,
		Secure:   false,
		HTTPOnly: true,
		SameSite: "Lax",
	})

	return nil
}
