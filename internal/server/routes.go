package server

import (
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func (s *Server) RegisterRoutes() {
	// Global Middleware
	s.App.Use(s.csrfHandler.CsrfMiddleware)
	s.App.Use(recover.New())

	/* Grouping Routes */
	apiV1 := s.App.Group("/api/v1")
	// CSRF Routes
	apiV1.Get("/csrf", s.csrfHandler.CsrfMiddleware, s.csrfHandler.CSRF)

	// Auth Group
	auth := s.App.Group("/auth/v1")
	auth.Use(s.authMiddleWare.AuthRouteMiddleware)

	// Auth Routes
	auth.Post("/register", s.authHandler.Register)
	auth.Post("/login", s.authHandler.Login)
	auth.Post("/change-password", s.authHandler.ChangePassword)
	auth.Post("/reset-password", s.authHandler.ResetPassword)
	auth.Post("/reset-password/verify/:token", s.authHandler.ResetPasswordConfirm)
	auth.Post("/logout", s.authHandler.Logout)

	// Auth Middleware
	apiV1.Use(s.authMiddleWare.AuthMiddleware)

	// User Routes
	apiV1.Post("/users", s.userHandler.CreateUser)
	apiV1.Get("/users", s.userHandler.GetUsers)
	apiV1.Get("/users/:id", s.userHandler.GetUserByID)
	apiV1.Get("/users/email/:email", s.userHandler.GetUserByEmail)
	apiV1.Get("/users/username/:username", s.userHandler.GetUserByUsername)
	apiV1.Put("/users/:id", s.userHandler.UpdateUser)
	apiV1.Delete("/users/:id/soft", s.userHandler.SoftDeleteUser)
	apiV1.Delete("/users/:id/hard", s.userHandler.HardDeleteUser)
	apiV1.Patch("/users", s.userHandler.UpdateSelf)
	apiV1.Delete("/users", s.userHandler.SoftDeleteSelf)

}
