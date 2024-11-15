package main

import (
	"archive/zip"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	logger  *zap.Logger
	workDir string // Working directory configuration
	// absDir  string // Absolute path to the working directory

	// Prometheus metrics
	fileOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "file_manager_operations_total",
		Help: "The total number of file operations",
	}, []string{"operation", "user"})

	// activeUsers = promauto.NewGauge(prometheus.GaugeOpts{
	// 	Name: "file_manager_active_users",
	// 	Help: "The number of active users",
	// })

	lastActivityTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "file_manager_last_activity_timestamp",
		Help: "Timestamp of the last activity by user",
	}, []string{"user"})

	// User last action tracking
	userLastActions      = make(map[string]*UserAction)
	userLastActionsMutex sync.RWMutex

	prefixPath string // Add this for prefix path configuration
)

func init() {
	var err error
	if os.Getenv("DEBUG") == "true" {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		fmt.Printf("Can't initialize zap logger: %v\n", err)
		os.Exit(1)
	}

	// Set working directory from environment variable
	workDir = os.Getenv("WORK_DIR")
	if workDir == "" {
		logger.Error("WORK_DIR environment variable not set")
		os.Exit(1)
	}

	// Convert workDir to an absolute path
	workDir, err = filepath.Abs(workDir)
	if err != nil {
		logger.Error("Failed to resolve absolute path for workDir", zap.Error(err))
		os.Exit(1)
	}

	// Validate working directory
	if _, err := os.Stat(workDir); os.IsNotExist(err) {
		logger.Error("Configured working directory does not exist", zap.String("workDir", workDir))
		os.Exit(1)
	}

	logger.Info("Working directory configured", zap.String("workDir", workDir))

	// Get prefix path from environment variable
	prefixPath = os.Getenv("PREFIX_PATH")
	if prefixPath != "" {
		// Ensure prefix path starts with / and doesn't end with /
		prefixPath = "/" + strings.Trim(prefixPath, "/")
		logger.Info("Using prefix path", zap.String("prefixPath", prefixPath))
	}
}

func fileExt(name string) string {
	logger.Debug("fileExt called", zap.String("name", name))
	return strings.TrimPrefix(filepath.Ext(name), ".")
}

func isTextFile(fileName string) bool {
	logger.Debug("isTextFile called", zap.String("fileName", fileName))
	textExtensions := []string{".txt", ".md", ".go", ".html", ".css", ".js"}
	for _, ext := range textExtensions {
		if strings.HasSuffix(fileName, ext) {
			return true
		}
	}
	return false
}

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"parentDir": func(dir string) string {
		logger.Debug("parentDir called", zap.String("dir", dir))
		return filepath.Dir(dir)
	},
	"isTextFile": isTextFile,
	"fileExt":    fileExt,
	"eq":         func(a, b string) bool { return a == b }, // Add equality function
	"workDir":    func() string { return workDir },         // Add workDir function
}).ParseGlob("templates/*.html"))

type User struct {
	Username string
	Password string
	ReadOnly bool
}

// var users = map[string]User{
// 	"admin": {"admin", "password", false},
// 	"guest": {"guest", "guestpass", true},
// }

type FileInfo struct {
	Name    string
	IsDir   bool
	Size    int64
	ModTime time.Time
}

var supportedLanguages = []string{"en", "es", "fr", "de"}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*") // Change "*" to your frontend's origin in production
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

type TemplateData struct {
	Files      []FileInfo
	Dir        string
	Query      string
	WorkDir    string
	CSRFToken  string
	PrefixPath string
}

// Add this struct for audit logs
type AuditLog struct {
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Timestamp time.Time `json:"timestamp"`
}

// Add this function to handle audit logging
func logAudit(c *gin.Context, action, resource string) {
	user, _, _ := c.Request.BasicAuth()
	if user == "" {
		user = "anonymous"
	}

	timestamp := time.Now()
	auditLog := AuditLog{
		User:      user,
		Action:    action,
		Resource:  resource,
		Timestamp: timestamp,
	}

	// Update Prometheus metrics
	fileOperations.WithLabelValues(action, user).Inc()
	// Add timestamp metric (Unix timestamp in seconds)
	lastActivityTime.WithLabelValues(user).Set(float64(timestamp.Unix()))

	// Update user's last action
	userLastActionsMutex.Lock()
	userLastActions[user] = &UserAction{
		Action:    action,
		Resource:  resource,
		Timestamp: auditLog.Timestamp,
	}
	userLastActionsMutex.Unlock()

	// Log to console using zap with "audit: " prefix
	logger.Info("audit: ",
		zap.String("user", auditLog.User),
		zap.String("action", auditLog.Action),
		zap.String("resource", auditLog.Resource),
		zap.Time("timestamp", auditLog.Timestamp))

	// Write to audit.log file with "audit: " prefix
	f, err := os.OpenFile("audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("Failed to open audit log file", zap.Error(err))
		return
	}
	defer f.Close()

	logEntry := fmt.Sprintf("audit: [%s] User '%s' %s '%s'\n",
		auditLog.Timestamp.Format("2006-01-02 15:04:05"),
		auditLog.User,
		auditLog.Action,
		auditLog.Resource)

	if _, err := f.WriteString(logEntry); err != nil {
		logger.Error("Failed to write to audit log", zap.Error(err))
	}
}

// Add this struct for tracking user actions
type UserAction struct {
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Timestamp time.Time `json:"timestamp"`
}

// Add this handler for user last actions
func getUserLastActionHandler(c *gin.Context) {
	userLastActionsMutex.RLock()
	defer userLastActionsMutex.RUnlock()

	c.JSON(http.StatusOK, userLastActions)
}

// Add this struct for media response
type MediaResponse struct {
	Path      string    `json:"path"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Type      string    `json:"type"`
	ModTime   time.Time `json:"mod_time"`
	Extension string    `json:"extension"`
}

// Add this handler for media files
func mediaHandler(c *gin.Context) {
	logger.Debug("mediaHandler called")

	// Get current directory
	currentDir := c.Query("dir")
	if currentDir == "" {
		currentDir = "."
	}
	currentDir = filepath.Clean(currentDir)

	// Get media type filter
	mediaType := c.Query("type") // "video", "image", or empty for all

	fullPath := filepath.Join(workDir, currentDir)
	files, err := os.ReadDir(fullPath)
	if err != nil {
		logger.Error("Failed to read directory", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read directory"})
		return
	}

	var mediaFiles []MediaResponse
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			continue
		}

		// Skip directories
		if info.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(file.Name()))
		var fileType string

		// Determine file type
		switch ext {
		case ".mp4", ".webm", ".ogg":
			fileType = "video"
		case ".jpg", ".jpeg", ".png", ".gif":
			fileType = "image"
		default:
			continue // Skip non-media files
		}

		// Apply media type filter
		if mediaType != "" && mediaType != fileType {
			continue
		}

		mediaFiles = append(mediaFiles, MediaResponse{
			Path:      filepath.Join(currentDir, file.Name()),
			Name:      file.Name(),
			Size:      info.Size(),
			Type:      fileType,
			ModTime:   info.ModTime(),
			Extension: ext,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"media_files": mediaFiles,
		"directory":   currentDir,
		"total":       len(mediaFiles),
	})
}

// Add this handler for serving media files
func serveMediaHandler(c *gin.Context) {
	filePath := c.Param("filepath")
	if filePath == "" {
		c.String(http.StatusBadRequest, "No file specified")
		return
	}

	// Remove leading slash from filepath parameter
	filePath = strings.TrimPrefix(filePath, "/")

	// Clean and validate the path
	cleanPath := filepath.Clean(filePath)
	fullPath := filepath.Join(workDir, cleanPath)

	logger.Debug("Media request",
		zap.String("filePath", filePath),
		zap.String("cleanPath", cleanPath),
		zap.String("fullPath", fullPath))

	// Validate path is within workDir
	if !strings.HasPrefix(fullPath, workDir) {
		logger.Error("Path traversal attempt", zap.String("path", fullPath))
		c.String(http.StatusForbidden, "Access denied")
		return
	}

	// Check if file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		logger.Error("File not found", zap.String("path", fullPath))
		c.String(http.StatusNotFound, "File not found")
		return
	}

	// Serve the file
	c.File(fullPath)
}

func main() {

	logger.Debug("main called")
	defer logger.Sync()

	if err := loadTranslations(); err != nil {
		logger.Error("Failed to load translations", zap.Error(err))
		os.Exit(1)
	}

	r := gin.Default()
	r.Use(CORSMiddleware())
	r.Use(CSRFMiddleware())

	// Add static file server
	var routerGroup *gin.RouterGroup
	if prefixPath != "" {
		routerGroup = r.Group(prefixPath)
		routerGroup.Static("/static", "./static")
		// Add media endpoint
		routerGroup.GET("/media/*filepath", serveMediaHandler)
	} else {
		routerGroup = r.Group("/")
		r.Static("/static", "./static")
		r.GET("/media/*filepath", serveMediaHandler)
	}

	// Update all routes to use the router group
	routerGroup.GET("/", fileHandler)
	routerGroup.GET("/edit", editHandler)
	routerGroup.POST("/upload", uploadHandler)
	routerGroup.POST("/download", downloadHandler)
	routerGroup.POST("/delete", deleteHandler)
	routerGroup.POST("/save", saveHandler)
	routerGroup.POST("/preview", previewFileHandler)
	routerGroup.POST("/chmod", chmodHandler)
	routerGroup.POST("/create", createHandler)
	routerGroup.POST("/copy", copyFileHandler)
	routerGroup.POST("/compress", compressFilesHandler)
	routerGroup.POST("/move", moveHandler)
	routerGroup.POST("/files", listFilesHandler)
	routerGroup.POST("/set-language", setLanguageHandler)
	routerGroup.GET("/language-options", languageOptionsHandler)
	routerGroup.GET("/metrics", gin.WrapH(promhttp.Handler()))
	routerGroup.GET("/user-actions", getUserLastActionHandler)
	routerGroup.GET("/api/media", mediaHandler)

	logger.Info("Server started at 0.0.0.0:8081")
	r.Run("0.0.0.0:8081")
}

// func authMiddleware(c *gin.Context) {
// 	logger.Debug("authMiddleware called")
// 	user, pass, ok := c.Request.BasicAuth()
// 	if !ok {
// 		c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
// 		c.AbortWithStatus(http.StatusUnauthorized)
// 		return
// 	}
// 	currentUser, valid := validateUser(user, pass)
// 	if !valid {
// 		c.AbortWithStatus(http.StatusUnauthorized)
// 		return
// 	}
// 	if currentUser.ReadOnly && (c.Request.Method == http.MethodPost || c.Request.Method == http.MethodDelete) {
// 		c.AbortWithStatus(http.StatusForbidden)
// 		return
// 	}
// 	c.Next()
// }

// func validateUser(username, password string) (User, bool) {
// 	logger.Debug("validateUser called", zap.String("username", username))
// 	user, exists := users[username]
// 	if !exists || user.Password != password {
// 		return User{}, false
// 	}
// 	return user, true
// }

func fileHandler(c *gin.Context) {
	logger.Debug("fileHandler called")
	user, _, _ := c.Request.BasicAuth()
	logger.Info("Accessing fileHandler", zap.String("user", user))

	// Get and clean the requested directory path
	requestedDir := c.Query("dir")
	if requestedDir == "" {
		requestedDir = "."
	}

	// Get search query
	searchQuery := strings.ToLower(c.Query("search"))

	// Clean and validate the path
	cleanDir := filepath.Clean(requestedDir)
	if cleanDir == ".." || strings.Contains(cleanDir, "../") {
		logger.Error("Path traversal attempt", zap.String("path", cleanDir))
		c.String(http.StatusForbidden, "Access denied")
		return
	}

	fullPath := filepath.Join(workDir, cleanDir)

	// Debug logging for directory path
	logger.Debug("Directory request",
		zap.String("requestedDir", requestedDir),
		zap.String("cleanDir", cleanDir),
		zap.String("fullPath", fullPath),
		zap.String("searchQuery", searchQuery))

	// Ensure the path is within workDir
	if !strings.HasPrefix(fullPath, workDir) {
		logger.Error("Path traversal attempt", zap.String("path", fullPath))
		c.String(http.StatusForbidden, "Access denied")
		return
	}

	// Check if directory exists
	dirInfo, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Error("Directory does not exist", zap.String("path", fullPath))
			c.String(http.StatusNotFound, "Directory not found")
			return
		}
		logger.Error("Failed to stat directory", zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	if !dirInfo.IsDir() {
		logger.Error("Path is not a directory", zap.String("path", fullPath))
		c.String(http.StatusBadRequest, "Not a directory")
		return
	}

	// Read directory contents
	files, err := os.ReadDir(fullPath)
	if err != nil {
		logger.Error("Failed to read directory", zap.String("dir", fullPath), zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	// Process files and apply search filter
	var fileInfos []FileInfo
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			continue
		}

		// Apply search filter if search query exists
		if searchQuery != "" {
			fileName := strings.ToLower(file.Name())
			if !strings.Contains(fileName, searchQuery) {
				continue
			}
		}

		fileInfos = append(fileInfos, FileInfo{
			Name:    file.Name(),
			IsDir:   file.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	// Generate CSRF token
	csrfToken := generateCSRFToken()

	// Set CSRF token in cookie
	c.SetCookie("csrf_token", csrfToken, 3600, "/", "", false, true)

	// Prepare template data
	data := TemplateData{
		Files:      fileInfos,
		Dir:        cleanDir,
		Query:      c.Query("search"),
		WorkDir:    workDir,
		CSRFToken:  csrfToken,
		PrefixPath: prefixPath,
	}

	if err := templates.ExecuteTemplate(c.Writer, "index.html", data); err != nil {
		logger.Error("Failed to execute template", zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
	}
}

func uploadHandler(c *gin.Context) {
	logger.Debug("uploadHandler called")

	// Get the current directory from the form
	dir := c.PostForm("dir")
	if dir == "" {
		dir = "."
	}

	// Clean and construct the full upload path
	cleanDir := filepath.Clean(dir)
	uploadPath := filepath.Join(workDir, cleanDir)

	// Ensure the upload path exists and is within workDir
	if !strings.HasPrefix(uploadPath, workDir) {
		logger.Error("Path traversal attempt", zap.String("path", uploadPath))
		c.String(http.StatusForbidden, "Access denied")
		return
	}

	// Create the directory if it doesn't exist
	if err := os.MkdirAll(uploadPath, 0755); err != nil {
		logger.Error("Failed to create upload directory", zap.String("dir", uploadPath), zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to create upload directory")
		return
	}

	form, err := c.MultipartForm()
	if err != nil {
		logger.Error("Failed to parse multipart form", zap.Error(err))
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	files := form.File["uploadfiles"]
	if len(files) == 0 {
		c.String(http.StatusBadRequest, "No files uploaded")
		return
	}

	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			logger.Error("Failed to open uploaded file", zap.String("filename", fileHeader.Filename), zap.Error(err))
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		defer file.Close()

		safeFileName := filepath.Clean(fileHeader.Filename)
		targetPath := filepath.Join(uploadPath, safeFileName)

		// Create the file
		out, err := os.Create(targetPath)
		if err != nil {
			logger.Error("Failed to create file", zap.String("filename", safeFileName), zap.Error(err))
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		defer out.Close()

		// Copy the file contents
		size, err := io.Copy(out, file)
		if err != nil {
			logger.Error("Failed to copy file", zap.String("filename", safeFileName), zap.Error(err))
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		logger.Info("File uploaded successfully",
			zap.String("filename", safeFileName),
			zap.String("dir", uploadPath),
			zap.Int64("size", size))

		logAudit(c, "uploaded file", safeFileName)
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Files uploaded successfully",
	})
}

func downloadHandler(c *gin.Context) {
	logger.Debug("downloadHandler called")

	var requestBody struct {
		File string `json:"file"`
		Dir  string `json:"dir"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid request body")
		return
	}

	fileName := requestBody.File
	if fileName == "" {
		c.String(http.StatusBadRequest, "File not specified")
		return
	}

	// Get current directory from request body or query
	currentDir := requestBody.Dir
	if currentDir == "" {
		currentDir = c.Query("dir")
		if currentDir == "" {
			currentDir = "."
		}
	}
	currentDir = filepath.Clean(currentDir)

	// Construct full file path
	filePath := filepath.Join(workDir, currentDir, fileName)
	absPath, err := filepath.Abs(filePath)
	if err != nil || !strings.HasPrefix(absPath, workDir) {
		logger.Warn("Invalid file path", zap.String("requestedPath", absPath))
		c.String(http.StatusForbidden, "Access denied")
		return
	}

	// Check if file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		logger.Error("File does not exist", zap.String("path", absPath))
		c.String(http.StatusNotFound, "File not found")
		return
	}

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(fileName)))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Expires", "0")
	c.Header("Cache-Control", "must-revalidate")
	c.Header("Pragma", "public")

	user, _, _ := c.Request.BasicAuth()
	logger.Info("File downloaded",
		zap.String("user", user),
		zap.String("filename", fileName),
		zap.String("path", absPath))

	logAudit(c, "downloaded file", fileName)
	c.File(absPath)
}

func deleteHandler(c *gin.Context) {
	logger.Debug("deleteHandler called")
	logger.Info("Received delete request", zap.String("request", c.Request.RequestURI))

	var requestBody struct {
		Files []string `json:"files"`
		Dir   string   `json:"dir"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(requestBody.Files) == 0 {
		c.String(http.StatusBadRequest, "No files specified")
		return
	}

	// Get current directory
	currentDir := requestBody.Dir
	if currentDir == "" {
		currentDir = c.Query("dir")
		if currentDir == "" {
			currentDir = "."
		}
	}
	currentDir = filepath.Clean(currentDir)

	var deletedFiles []string
	for _, fileName := range requestBody.Files {
		cleanPath := filepath.Clean(fileName)
		filePath := filepath.Join(workDir, currentDir, cleanPath)

		if !strings.HasPrefix(filePath, workDir) {
			logger.Warn("Attempted directory traversal", zap.String("requestedPath", filePath))
			c.String(http.StatusForbidden, "Access denied")
			return
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			logger.Error("File does not exist", zap.String("path", filePath))
			c.String(http.StatusNotFound, "File not found: "+cleanPath)
			return
		}

		// Check if it's a directory
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			logger.Error("Failed to get file info", zap.String("path", filePath), zap.Error(err))
			c.String(http.StatusInternalServerError, "Failed to get file info: "+cleanPath)
			return
		}

		if fileInfo.IsDir() {
			// Remove directory and all contents
			err = os.RemoveAll(filePath)
		} else {
			// Remove single file
			err = os.Remove(filePath)
		}

		if err != nil {
			logger.Error("Failed to delete", zap.String("path", filePath), zap.Error(err))
			c.String(http.StatusInternalServerError, "Failed to delete: "+cleanPath)
			return
		}

		deletedFiles = append(deletedFiles, cleanPath)
		user, _, _ := c.Request.BasicAuth()
		logger.Info("Item deleted",
			zap.String("user", user),
			zap.String("path", cleanPath),
			zap.Bool("isDir", fileInfo.IsDir()))

		logAudit(c, "deleted", cleanPath)
	}

	if len(deletedFiles) > 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "Items deleted successfully",
			"deleted": deletedFiles,
		})
	} else {
		c.String(http.StatusOK, "No items were deleted")
	}
}

func editHandler(c *gin.Context) {
	logger.Debug("editHandler called")
	fileName := c.Query("file")
	if fileName == "" {
		c.String(http.StatusBadRequest, "File not specified")
		return
	}

	filePath := filepath.Join(workDir, fileName)
	content, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error("Failed to read file", zap.String("filename", fileName), zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	user, _, _ := c.Request.BasicAuth()
	logger.Info("File edited", zap.String("user", user), zap.String("filename", fileName), zap.String("dir", filepath.Dir(filePath)), zap.Int64("size", int64(len(content))))

	data := struct {
		FileName string
		Content  string
	}{
		FileName: fileName,
		Content:  string(content),
	}

	if err := templates.ExecuteTemplate(c.Writer, "edit.html", data); err != nil {
		logger.Error("Failed to execute template", zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
	}

	logAudit(c, "edited", fileName)
}

func saveHandler(c *gin.Context) {
	logger.Debug("saveHandler called")

	var requestBody struct {
		File    string `json:"file"`
		Content string `json:"content"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid request body")
		return
	}

	fileName := requestBody.File
	content := requestBody.Content

	filePath := filepath.Join(workDir, fileName)
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		logger.Error("Failed to write file", zap.String("filename", fileName), zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	user, _, _ := c.Request.BasicAuth()
	logger.Info("File saved", zap.String("user", user), zap.String("filename", fileName), zap.String("dir", filepath.Dir(filePath)), zap.Int64("size", int64(len(content))))

	dir := filepath.Dir(filePath)
	c.Redirect(http.StatusSeeOther, "/?dir="+dir)

	logAudit(c, "saved changes to", fileName)
}

func previewFileHandler(c *gin.Context) {
	logger.Debug("previewFileHandler called")

	var requestBody struct {
		File string `json:"file"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	filePath := filepath.Join(workDir, requestBody.File)

	// Check if file is a video
	ext := strings.ToLower(filepath.Ext(filePath))
	isVideo := ext == ".mp4" || ext == ".ogg" || ext == ".webm"

	if isVideo {
		// For video files, return video player HTML with proper styling and controls
		videoHTML := fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head>
				<title>Video Preview</title>
				<style>
					body {
						margin: 0;
						padding: 0;
						background: #000;
						display: flex;
						justify-content: center;
						align-items: center;
						min-height: 100vh;
					}
					.video-container {
						width: 80%%;
						max-width: 1200px;
					}
					video {
						width: 100%%;
						height: auto;
						max-height: 80vh;
					}
				</style>
			</head>
			<body>
				<div class="video-container">
					<video controls autoplay>
						<source src="/static/%s" type="video/%s">
						Your browser does not support the video tag.
					</video>
				</div>
			</body>
			</html>
		`, requestBody.File, strings.TrimPrefix(ext, "."))

		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, videoHTML)
		return
	}

	// For non-video files, continue with regular preview
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("Failed to open file", zap.String("filePath", filePath), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "File not found"})
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		logger.Error("Failed to read file", zap.String("filePath", filePath), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	c.String(http.StatusOK, string(content))
}

func chmodHandler(c *gin.Context) {
	logger.Debug("chmodHandler called")

	var requestBody struct {
		File string `json:"file"`
		Mode string `json:"mode"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid request body")
		return
	}

	// Clean and validate the file path
	fileName := filepath.Clean(requestBody.File)
	filePath := filepath.Join(workDir, fileName)

	// Validate the path is within workDir
	if !strings.HasPrefix(filePath, workDir) {
		logger.Error("Path traversal attempt", zap.String("path", filePath))
		c.String(http.StatusForbidden, "Invalid path")
		return
	}

	// Parse and validate the mode
	modeStr := requestBody.Mode
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		logger.Error("Invalid mode", zap.String("mode", modeStr), zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid mode")
		return
	}

	// Change the file permissions
	err = os.Chmod(filePath, os.FileMode(mode))
	if err != nil {
		logger.Error("Failed to change file mode", zap.String("filename", fileName), zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	user, _, _ := c.Request.BasicAuth()
	logger.Info("File permissions changed",
		zap.String("user", user),
		zap.String("filename", fileName),
		zap.String("path", filePath),
		zap.Uint32("mode", uint32(mode)))

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Permissions changed successfully",
		"file":    fileName,
		"mode":    modeStr,
	})

	logAudit(c, "changed permissions", fmt.Sprintf("%s to %s", fileName, modeStr))
}

func createHandler(c *gin.Context) {
	logger.Debug("createHandler called")

	var requestBody struct {
		Dir  string `json:"dir"`
		Name string `json:"name"`
		Type string `json:"type"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid request body")
		return
	}

	// Only allow directory creation
	if requestBody.Type != "directory" {
		logger.Error("Invalid creation type", zap.String("type", requestBody.Type))
		c.String(http.StatusBadRequest, "Only folder creation is allowed")
		return
	}

	// Clean and validate the folder name
	folderName := filepath.Clean(requestBody.Name)
	if folderName == "." || folderName == ".." || strings.Contains(folderName, "/") {
		logger.Error("Invalid folder name", zap.String("name", folderName))
		c.String(http.StatusBadRequest, "Invalid folder name")
		return
	}

	// Construct the full path
	currentDir := filepath.Clean(requestBody.Dir)
	fullPath := filepath.Join(workDir, currentDir, folderName)

	// Validate the path
	if !strings.HasPrefix(fullPath, workDir) {
		logger.Error("Path traversal attempt", zap.String("path", fullPath))
		c.String(http.StatusForbidden, "Invalid path")
		return
	}

	// Create the directory
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		logger.Error("Failed to create directory",
			zap.String("name", folderName),
			zap.String("path", fullPath),
			zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to create folder: "+err.Error())
		return
	}

	user, _, _ := c.Request.BasicAuth()
	logger.Info("Directory created",
		zap.String("user", user),
		zap.String("name", folderName),
		zap.String("path", fullPath))

	c.JSON(http.StatusOK, gin.H{
		"message": "Folder created successfully",
		"path":    fullPath,
	})

	logAudit(c, "created folder", folderName)
}

func compressFilesHandler(c *gin.Context) {
	logger.Debug("compressFilesHandler called")

	var requestBody struct {
		Files  []string `json:"files"`
		Output string   `json:"output"`
		Dir    string   `json:"dir"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(requestBody.Files) == 0 {
		c.String(http.StatusBadRequest, "No files specified")
		return
	}

	// Get current directory from request body or query
	currentDir := requestBody.Dir
	if currentDir == "" {
		currentDir = c.Query("dir")
		if currentDir == "" {
			currentDir = "."
		}
	}
	currentDir = filepath.Clean(currentDir)

	// Create temporary file for zip
	tempFile, err := os.CreateTemp("", "download-*.zip")
	if err != nil {
		logger.Error("Failed to create temp file", zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to create temporary file")
		return
	}
	tempPath := tempFile.Name()
	defer func() {
		tempFile.Close()
		os.Remove(tempPath)
	}()

	// Create zip writer
	zipWriter := zip.NewWriter(tempFile)
	defer zipWriter.Close()

	// Process each file
	for _, file := range requestBody.Files {
		// Clean and construct the full file path
		cleanName := filepath.Clean(file)
		filePath := filepath.Join(workDir, currentDir, cleanName)

		// Validate path
		if !strings.HasPrefix(filePath, workDir) {
			logger.Error("Invalid path", zap.String("path", filePath))
			c.String(http.StatusBadRequest, "Invalid path")
			return
		}

		// Check if file exists and get info
		_, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				logger.Error("File does not exist",
					zap.String("file", file),
					zap.String("path", filePath),
					zap.Error(err))
				c.String(http.StatusNotFound, fmt.Sprintf("File not found: %s", file))
				return
			}
			logger.Error("Failed to stat file", zap.String("file", file), zap.Error(err))
			c.String(http.StatusInternalServerError, "Failed to access file")
			return
		}

		// Add file to zip
		err = addFileToZip(zipWriter, filePath, cleanName)
		if err != nil {
			logger.Error("Failed to add to zip",
				zap.String("file", file),
				zap.Error(err))
			c.String(http.StatusInternalServerError, "Failed to compress files")
			return
		}
	}

	// Prepare file for download
	if _, err := tempFile.Seek(0, 0); err != nil {
		logger.Error("Failed to seek temp file", zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to prepare download")
		return
	}

	// Set download headers
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", "attachment; filename=download.zip")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Expires", "0")
	c.Header("Cache-Control", "must-revalidate")
	c.Header("Pragma", "public")

	// Serve the file
	http.ServeContent(c.Writer, c.Request, "download.zip", time.Now(), tempFile)

	user, _, _ := c.Request.BasicAuth()
	logger.Info("Files compressed and downloaded",
		zap.String("user", user),
		zap.Strings("files", requestBody.Files),
		zap.String("currentDir", currentDir))

	logAudit(c, "compressed", strings.Join(requestBody.Files, ", "))
}

func addFileToZip(zipWriter *zip.Writer, filePath string, zipPath string) error {
	logger.Debug("addFileToZip called",
		zap.String("filePath", filePath),
		zap.String("zipPath", zipPath))

	fileToZip, err := os.Open(filePath)
	if err != nil {
		logger.Error("Failed to open file", zap.String("filePath", filePath), zap.Error(err))
		return err
	}
	defer fileToZip.Close()

	info, err := fileToZip.Stat()
	if err != nil {
		logger.Error("Failed to get file info", zap.String("filePath", filePath), zap.Error(err))
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		logger.Error("Failed to create zip header", zap.String("filePath", filePath), zap.Error(err))
		return err
	}

	// Use the provided zip path
	header.Name = zipPath
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		logger.Error("Failed to create zip writer", zap.String("filePath", filePath), zap.Error(err))
		return err
	}

	_, err = io.Copy(writer, fileToZip)
	if err != nil {
		logger.Error("Failed to copy file to zip", zap.String("filePath", filePath), zap.Error(err))
	}
	return err
}

func copyFile(src, dst string) error {
	logger.Debug("copyFile called", zap.String("src", src), zap.String("dst", dst))
	sourceFile, err := os.Open(src)
	if err != nil {
		logger.Error("Failed to open source file", zap.String("src", src), zap.Error(err))
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		logger.Error("Failed to create destination file", zap.String("dst", dst), zap.Error(err))
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		logger.Error("Failed to copy file", zap.String("src", src), zap.String("dst", dst), zap.Error(err))
	}
	return err
}

func copyFileHandler(c *gin.Context) {
	logger.Debug("copyFileHandler called")

	var requestBody struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid request body")
		return
	}

	// Clean and construct the full source path
	srcPath := filepath.Join(workDir, requestBody.Src)

	// Clean and construct the full destination path
	dstPath := filepath.Join(workDir, requestBody.Dst, filepath.Base(requestBody.Src))

	// Validate paths
	if !strings.HasPrefix(srcPath, workDir) || !strings.HasPrefix(dstPath, workDir) {
		logger.Error("Invalid path", zap.String("src", srcPath), zap.String("dst", dstPath))
		c.String(http.StatusBadRequest, "Invalid path")
		return
	}

	// Create destination directory if it doesn't exist
	dstDir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		logger.Error("Failed to create destination directory", zap.String("dir", dstDir), zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to create destination directory")
		return
	}

	// Copy the file
	if err := copyFile(srcPath, dstPath); err != nil {
		logger.Error("Failed to copy file", zap.String("src", srcPath), zap.String("dst", dstPath), zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	user, _, _ := c.Request.BasicAuth()
	logger.Info("File copied", zap.String("user", user), zap.String("src", srcPath), zap.String("dst", dstPath))

	logAudit(c, "copied", fmt.Sprintf("from '%s' to '%s'", srcPath, dstPath))

	c.JSON(http.StatusOK, gin.H{
		"message": "File copied successfully",
		"src":     srcPath,
		"dst":     dstPath,
	})
}

func moveHandler(c *gin.Context) {
	logger.Debug("moveHandler called")

	var requestBody struct {
		Src      string `json:"src"`
		Dst      string `json:"dst"`
		Dir      string `json:"dir"`
		IsFolder bool   `json:"isFolder"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid request body")
		return
	}

	// Debug logging
	logger.Debug("Move request received",
		zap.String("src", requestBody.Src),
		zap.String("dst", requestBody.Dst),
		zap.String("dir", requestBody.Dir),
		zap.Bool("isFolder", requestBody.IsFolder))

	// Clean and construct paths
	srcPath := filepath.Join(workDir, requestBody.Dir, requestBody.Src)
	dstPath := filepath.Join(workDir, requestBody.Dir, requestBody.Dst, filepath.Base(requestBody.Src))

	// Debug logging
	logger.Debug("Constructed paths",
		zap.String("srcPath", srcPath),
		zap.String("dstPath", dstPath))

	// Validate paths
	if !strings.HasPrefix(srcPath, workDir) || !strings.HasPrefix(dstPath, workDir) {
		logger.Error("Invalid path", zap.String("src", srcPath), zap.String("dst", dstPath))
		c.String(http.StatusBadRequest, "Invalid path")
		return
	}

	// Check if source exists
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Error("Source file does not exist", zap.String("src", srcPath))
			c.String(http.StatusNotFound, "Source file not found")
			return
		}
		logger.Error("Failed to stat source", zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	// Create destination directory if it doesn't exist
	dstDir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		logger.Error("Failed to create destination directory", zap.String("dir", dstDir), zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to create destination directory")
		return
	}

	// Check if destination already exists
	if _, err := os.Stat(dstPath); err == nil {
		logger.Error("Destination already exists", zap.String("dst", dstPath))
		c.String(http.StatusConflict, "Destination already exists")
		return
	}

	// Perform the move
	if err := os.Rename(srcPath, dstPath); err != nil {
		logger.Error("Failed to move file", zap.String("src", srcPath), zap.String("dst", dstPath), zap.Error(err))
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	logger.Info("File moved successfully",
		zap.String("src", srcPath),
		zap.String("dst", dstPath),
		zap.Bool("isDir", srcInfo.IsDir()))

	logAudit(c, "moved", fmt.Sprintf("from '%s' to '%s'", srcPath, dstPath))

	c.JSON(http.StatusOK, gin.H{
		"message": "File moved successfully",
		"src":     srcPath,
		"dst":     dstPath,
	})
}

func setLanguageHandler(c *gin.Context) {
	var requestBody struct {
		Language string `json:"language"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.String(http.StatusBadRequest, "Invalid request body")
		return
	}

	language := requestBody.Language
	logger.Debug("Attempting to set language", zap.String("language", language))

	if !isSupportedLanguage(language) {
		logger.Error("Language not supported", zap.String("language", language))
		c.String(http.StatusBadRequest, "Language not supported")
		return
	}

	// Set the language in the session or cookie
	c.SetCookie("language", language, 3600, "/", "", false, true)
	logger.Info("Language set successfully", zap.String("language", language))
	c.Redirect(http.StatusSeeOther, "/")
}

func isSupportedLanguage(language string) bool {
	for _, lang := range supportedLanguages {
		if lang == language {
			return true
		}
	}
	return false
}

type Translation struct {
	Name        string            `json:"name"`
	Code        string            `json:"code"`
	Translation map[string]string `json:"translation"`
}

type Language struct {
	Name        string            `json:"name"`
	Code        string            `json:"code"`
	Translation map[string]string `json:"translation"`
}

var languages []Language

var translations map[string]map[string]string

func loadTranslations() error {
	logger.Debug("Loading translations from file")
	file, err := os.Open("translation.json")
	if err != nil {
		logger.Error("Failed to open translation file", zap.Error(err))
		return err
	}
	defer file.Close()

	byteValue, _ := io.ReadAll(file)
	var data struct {
		Language []Language `json:"language"`
	}
	err = json.Unmarshal(byteValue, &data)
	if err != nil {
		logger.Error("Failed to parse translation file", zap.Error(err))
		return err
	}

	languages = data.Language
	translations = make(map[string]map[string]string)
	for _, lang := range languages {
		translations[lang.Code] = lang.Translation
	}
	logger.Info("Translations loaded successfully", zap.Int("count", len(languages)))
	return nil
}

// func getSupportedLanguages() []Language {
//     return languages
// }

func languageOptionsHandler(c *gin.Context) {
	// for _, lang := range languages {
	//     logger.Debug("Language option", zap.String("name", lang.Name))
	// }
	c.JSON(http.StatusOK, languages)
}

func listFilesHandler(c *gin.Context) {
	var requestBody struct {
		Dir string `json:"dir"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	dir := requestBody.Dir
	if dir == "" {
		dir = "."
	}

	fullPath := filepath.Join(workDir, dir)
	files, err := os.ReadDir(fullPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var fileInfos []FileInfo
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			continue
		}
		fileInfos = append(fileInfos, FileInfo{
			Name:    file.Name(),
			IsDir:   file.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	c.JSON(http.StatusOK, gin.H{"files": fileInfos})
}

func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" {
			clientToken := c.GetHeader("X-CSRF-Token")
			cookieToken, _ := c.Cookie("csrf_token")

			if clientToken == "" || cookieToken == "" || clientToken != cookieToken {
				logger.Error("CSRF token validation failed",
					zap.String("clientToken", clientToken),
					zap.String("cookieToken", cookieToken))
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		c.Next()
	}
}
