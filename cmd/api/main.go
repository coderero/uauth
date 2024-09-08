package main

import (
	"log"

	"github.com/coderero/paas-project/internal/server"
)

func main() {
	app := server.New()

	app.RegisterRoutes()
	if err := app.Listen(":8080"); err != nil {
		log.Fatal(err)
	}
}
