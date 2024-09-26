package server

import (
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func (s *Server) RegisterRoutes() {
	/* Configuration of the Middlewares */

	// Global Middleware
	s.App.Use(s.csrfHandler.CsrfMiddleware)
	s.App.Use(recover.New())

	/* Grouping Routes */
	apiV1 := s.App.Group("/api/v1")
	// CSRF Routes
	apiV1.Get("/csrf", s.csrfHandler.CsrfMiddleware, s.csrfHandler.CSRF)
	// Auth Middleware
	apiV1.Use(s.authMiddleWare.AuthMiddleware)

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
}
