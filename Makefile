name="codepaas"
version="0.1.0"
build-api:
	@echo "Building API"
	@go build  -ldflags "-X main.name=$(name) -X main.version=$(version)" -o bin/api cmd/api/main.go
	@echo "API build complete"

run-api:
	@echo "Running API"
	@go run cmd/api/main.go

.PHONY: build-api run-api