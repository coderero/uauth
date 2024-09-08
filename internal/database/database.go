package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"
)

// Service is the interface that provides database methods.
type Service interface {
	// DB returns the database connection
	DB() *sql.DB

	// Health returns the health of the database
	Health() fiber.Map

	// Migrate migrates the database schema
	Migrate() error

	// Close closes the database connection
	Close() error
}

// service is the implementation of the Service interface.
type service struct {
	db *sql.DB
}

var (
	database   = os.Getenv("DB_DATABASE")
	password   = os.Getenv("DB_PASSWORD")
	username   = os.Getenv("DB_USERNAME")
	port       = os.Getenv("DB_PORT")
	host       = os.Getenv("DB_HOST")
	schema     = os.Getenv("DB_SCHEMA")
	dbInstance *service
)

// New creates a new database service.
func New() Service {
	// Return the instance if it already exists
	if dbInstance != nil {
		return dbInstance
	}

	// Create a new database connection
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&search_path=%s", username, password, host, port, database, schema)
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Set the database instance
	dbInstance = &service{
		db: db,
	}
	return dbInstance
}

// DB returns the database connection.
func (s *service) DB() *sql.DB {
	return s.db
}

// Health returns the health of the database connection.
func (s *service) Health() fiber.Map {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(fiber.Map)

	// Ping the database
	err := s.db.PingContext(ctx)
	if err != nil {
		stats["database_status"] = "down"
		stats["error"] = fmt.Sprintf("db down: %v", err)
		log.Fatalf(fmt.Sprintf("db down: %v", err)) // Log the error and terminate the program
		return stats
	}

	// Database is up, add more statistics
	stats["database_status"] = "up"
	stats["message"] = "It's healthy"

	// Get database stats (like open connections, in use, idle, etc.)
	dbStats := s.db.Stats()
	stats["open_connections"] = strconv.Itoa(dbStats.OpenConnections)
	stats["in_use"] = strconv.Itoa(dbStats.InUse)
	stats["idle"] = strconv.Itoa(dbStats.Idle)
	stats["wait_count"] = strconv.FormatInt(dbStats.WaitCount, 10)
	stats["wait_duration"] = dbStats.WaitDuration.String()
	stats["max_idle_closed"] = strconv.FormatInt(dbStats.MaxIdleClosed, 10)
	stats["max_lifetime_closed"] = strconv.FormatInt(dbStats.MaxLifetimeClosed, 10)

	// Evaluate stats to provide a health message
	if dbStats.OpenConnections > 40 { // Assuming 50 is the max for this example
		stats["message"] = "The database is experiencing heavy load."
	}

	if dbStats.WaitCount > 1000 {
		stats["message"] = "The database has a high number of wait events, indicating potential bottlenecks."
	}

	if dbStats.MaxIdleClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many idle connections are being closed, consider revising the connection pool settings."
	}

	if dbStats.MaxLifetimeClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many connections are being closed due to max lifetime, consider increasing max lifetime or revising the connection usage pattern."
	}

	return stats
}

// Migrate migrates the database schema.
func (s *service) Migrate() error {
	//Grab the schema file from the migrations folder
	file, err := os.ReadFile("./internal/database/migrations/init_schema.sql")
	if err != nil {
		return err
	}

	//Execute the schema file
	_, err = s.db.Exec(string(file))

	// Check if the error was due to the schema already existing
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
	}

	//TODO: Add Database Object Migration (i.e. Triggers, Functions, etc.)
	return err
}

// Close closes the database connection.
func (s *service) Close() error {
	log.Printf("Disconnected from database: %s", database)
	return s.db.Close()
}
