name="codepaas"
version="0.1.0"
run:
	@echo "Running API"
	@go run cmd/api/main.go

build-api:
	@echo "Building API"
	@go build  -ldflags "-X main.name=$(name) -X main.version=$(version)" -o bin/api cmd/api/main.go
	@echo "API build complete"

run-api:
	@echo "Running API"
	@go run cmd/api/main.go

test:
	@echo "Running tests"
	@go test -v ./...

.PHONY: build-api run-api