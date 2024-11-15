# Variables
BINARY_NAME=gofs
DOCKER_IMAGE=registry.gitlab.com/fintech-sandpit/cloudbrowser
DOCKER_TAG=filebrowser-1.0.0

# Go related variables
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GOFILES=$(wildcard *.go)

# Build the project
build:
	@echo "Building..."
	@go build -o $(BINARY_NAME) .

# Clean build files
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME)
	@rm -f $(GOBIN)/$(BINARY_NAME)

# Run tests
test:
	@echo "Testing..."
	@go test -v ./...

# Build docker image
docker-build:
	@echo "Building docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Run docker container
docker-run:
	@echo "Running docker container..."
	docker run -d \
		-p 8081:8081 \
		-v $(PWD)/data:/data \
		--name $(DOCKER_TAG) \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

# Stop docker container
docker-stop:
	@echo "Stopping docker container..."
	docker stop $(DOCKER_TAG)


# Push docker image
docker-push:
	@echo "Pushing docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-delete:
	@echo "Deleting docker image..."
	docker rm $(DOCKER_TAG)

# Development run
dev:
	@echo "Running development server..."
	@go run main.go

# All target
all: clean build

# Help target
help:
	@echo "Available targets:"
	@echo "  build        - Build the project"
	@echo "  clean        - Clean build files"
	@echo "  test         - Run tests"
	@echo "  docker-build - Build docker image"
	@echo "  docker-run   - Run docker container"
	@echo "  docker-stop  - Stop docker container"
	@echo "  docker-push  - Push docker image"
	@echo "  dev          - Run development server"
	@echo "  all          - Clean and build"

.PHONY: build clean test docker-build docker-run docker-stop docker-push dev all help