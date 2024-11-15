# GoFS - Go File Manager

GoFS is a modern, secure, and feature-rich file manager written in Go. It provides a web-based interface for managing files and directories with support for various operations including file upload, download, preview, and more.

## Features

- 📁 File and directory management
- 🔍 File search functionality
- 📤 File upload with drag and drop support
- 📥 File download
- 👀 File preview (images, videos, text files)
- 🔒 Secure file operations
- 🎯 CSRF protection
- 🎨 Modern and responsive UI
- 🎥 Video player integration
- 📝 Text file editing
- 🔑 File permission management

## Quick Start

### Using Docker

```bash
# Build the Docker image
make docker-build
# Run the container
make docker-run
```

### Manual Installation

1. Clone the repository:

```bash
git clone https://github.com/Kamukage3e/gofs.git
cd gofs
```

2. Build the project:
```bash
make build
```

3. Run the application:

```bash
make dev
```


## Configuration

The application can be configured using environment variables:

- `WORK_DIR`: Directory to manage (default: ./data)
- `DEBUG`: Enable debug mode (true/false)
- `PORT`: Server port (default: 8081)

## Development

### Prerequisites

- Go 1.21 or higher
- Make

### Available Make Commands

- `make build`: Build the project
- `make clean`: Clean build files
- `make test`: Run tests
- `make docker-build`: Build Docker image
- `make docker-run`: Run Docker container
- `make docker-stop`: Stop Docker container
- `make dev`: Run development server
- `make all`: Clean and build

## API Endpoints

- `GET /`: Main file manager interface
- `POST /upload`: Upload files
- `GET /download`: Download files
- `POST /delete`: Delete files
- `GET /edit`: Edit text files
- `POST /save`: Save edited files
- `POST /preview`: Preview files
- `POST /chmod`: Change file permissions
- `POST /create`: Create files/directories
- `POST /copy`: Copy files
- `POST /compress`: Compress files

## Security

- CSRF protection
- Path traversal prevention
- Input sanitization
- Secure file operations
- Content Security Policy

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Kamukage3e

## Acknowledgments

- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [Vidstack Player](https://www.vidstack.io/)
- [Bootstrap](https://getbootstrap.com/)



