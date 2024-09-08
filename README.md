# Codiman - Task Management System Server
This is the server side of the Codiman Task Management System. It is built using Go,Fiber, PostgresSQL and Redis.

## Features
- User Authentication
- Task Management
- Role Management

## Installation
1. Clone the repository
2. Install the dependencies
3. Create a `.env` file and add the following environment variables
```
TOKEN_KEY= # A random string

SMTP_HOST= # SMTP Server Host
SMTP_PORT= # SMTP Server Port
SMTP_FROM= # Email address to send emails from
SMTP_USERNAME= # SMTP Username
SMTP_PASSWORD= # SMTP Password

DB_DATABASE= # Postgres Database Name
DB_USERNAME= # Postgres Username
DB_PASSWORD= # Postgres Password
DB_HOST= # Postgres Host
DB_PORT= # Postgres Port
DB_SCHEMA= # Postgres Schema

CACHE_ADDRESS= # Redis Address
CACHE_PASSWORD= # Redis Password
CACHE_DATABASE= # Redis Database
```
4. Run the server
There are three ways to run the server as of now
- Using Makefile
```bash
make run
```
- Using go run
```bash
go run cmd/api/main.go
```
- Using air (Hot Reload) - Install air using `go get -u github.com/cosmtrek/air`
```bash
air
```

## Directory Structure
```
.
├── .air.toml
├── .env
├── .env.example
├── .github
│   └── workflow
│       └── initigration.yaml
├── .gitignore
├── Makefile
├── README.md
├── api
│   ├── handlers
│   │   ├── auth.go
│   │   └── csrf.go
│   ├── middlewares
│   │   └── auth.go
│   └── models
│       └── user.go
├── bin
│   ├── .gitkeep
│   ├── api
│   └── build-errors.log
├── certs
│   ├── .gitkeep
│   ├── private.pem
│   └── public.pem
├── cmd
│   └── api
│       └── main.go
├── docs
│   └── .gitkeep
├── go.mod
├── go.sum
├── internal
│   ├── cache
│   │   ├── cache.go
│   │   └── jwt.go
│   ├── database
│   │   ├── database.go
│   │   ├── migrations
│   │   │   └── init_schema.sql
│   │   └── user_repository.go
│   ├── server
│   │   ├── routes.go
│   │   └── server.go
│   ├── services
│   │   ├── auth.go
│   │   ├── crypt.go
│   │   ├── jwt.go
│   │   └── smtp.go
│   ├── types
│   │   ├── api.go
│   │   ├── jwt.go
│   │   └── premitive.go
│   └── utils
│       ├── basic.go
│       ├── server.go
│       └── validation.go
├── static
│   └── .gitkeep
└── tests
    └── .gitkeep
```

## API Documentation
The API documentation can be found [here](https://documenter.getpostman.com/view/11636691/TzJx8w7T)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Author
- [Mohit Sharma](github.com/coderere)

## Acknowledgements
- [Fiber](github.com/gofiber/fiber)
- [PGX](github.com/jackc/pgx)
- [Redis](github.com/go-redis/redis)




