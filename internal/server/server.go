package server

import (
	"log"

	"github.com/coderero/paas-project/api/handlers"
	"github.com/coderero/paas-project/api/middlewares"
	"github.com/coderero/paas-project/internal/cache"
	"github.com/coderero/paas-project/internal/database"
	"github.com/coderero/paas-project/internal/services"
	"github.com/coderero/paas-project/internal/utils"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"

	_ "github.com/joho/godotenv/autoload"
)

// Server Configuration Structure
type Server struct {
	*fiber.App
	// validators
	validator *validator.Validate

	// services
	db            database.Service
	cache         cache.Service
	jwtCache      cache.JwtCache
	userRepo      database.UserRepository
	cryptoService services.CryptService
	authService   services.AuthServicer
	jwtService    services.JwtService

	// middlewares
	authMiddleWare middlewares.AuthMiddleware

	// handlers
	authHandler *handlers.AuthHandler
	csrfHandler *handlers.CsrfHandler
	userHandler *handlers.UserHandler
}

func New() *Server {
	// Initialize the database
	db := database.New()
	if err := db.Migrate(); err != nil {
		log.Fatal(err)
	}

	// Initialize the cache
	redisCache := cache.New()

	// Initialize the validator
	validatorInstance := validator.New()
	validatorInstance.RegisterTagNameFunc(utils.ValidatorTagFunc)

	// Initialize the jwt cache
	jwtCache := cache.NewJwtCache(redisCache.Cache())

	// Initialize the user repository
	userRepo := database.NewUserRepository(db)

	// Initialize the crypt service
	cryptoService := services.NewCryptService(15, 8, 1, 32, 12)

	// Initialize the jwt service
	jwtService := services.NewJwtService(jwtCache)

	// Intialize the user service
	userService := services.NewUserService(userRepo, cryptoService)

	// Initialize the middleware service
	authMiddleWare := middlewares.NewAuthMiddleware(jwtService)

	// Initialize the auth service
	authService := services.NewAuthService(cryptoService, userRepo, jwtService)

	// Initialize the user handler
	userHandler := handlers.NewUserHandler(validatorInstance, userService)

	return &Server{
		App: fiber.New(
			fiber.Config{
				ErrorHandler: utils.ErrorHandler,
			},
		),
		db:             db,
		cache:          redisCache,
		validator:      validatorInstance,
		jwtCache:       jwtCache,
		userRepo:       userRepo,
		cryptoService:  cryptoService,
		jwtService:     jwtService,
		authService:    authService,
		authMiddleWare: authMiddleWare,
		csrfHandler:    handlers.NewCsrfHandler(redisCache),
		authHandler:    handlers.NewAuthHandler(authService, validatorInstance),
		userHandler:    userHandler,
	}
}
