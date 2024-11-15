# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install required build tools
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o gofs .

# Final stage
FROM alpine:latest

WORKDIR /app

# Install required runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy the binary from builder
COPY --from=builder /app/gofs .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY --from=builder /app/translation.json ./translation.json

# Create work directory
RUN mkdir -p /data

# Set environment variables
ENV WORK_DIR=/data
ENV GIN_MODE=release

# Expose port
EXPOSE 8081

# Run the application
CMD ["./gofs"]