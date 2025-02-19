BINARY_NAME=oslogin-key-manager
BUILD_DIR=build

ifeq ($(shell go env GO111MODULE),on)
    MOD_FLAG=-mod=vendor
else
    MOD_FLAG=
endif

all: build

build:
	@echo "Building the application..."
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) $(MOD_FLAG) .

clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)

.PHONY: test

test:
	@echo "Running tests..."
	go test ./...

tidy:
	@echo "Tidying up..."
	go mod tidy

vendor:
	@echo "Vendoring dependencies..."
	go mod vendor
