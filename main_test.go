package main

import (
    "bytes"

    "mime/multipart"
    "net/http"
    "net/http/httptest"
    "os"

    "strings"
    "testing"

    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"
)

func setupRouter() *gin.Engine {
    r := gin.Default()
    // r.Use(authMiddleware)
    r.GET("/", fileHandler)
    r.POST("/upload", uploadHandler)
    r.GET("/download", downloadHandler)
    r.POST("/delete", deleteHandler)
    r.GET("/edit", editHandler)
    r.POST("/save", saveHandler)
    // r.GET("/preview", previewHandler)
    r.POST("/chmod", chmodHandler)
    r.POST("/create", createHandler)
    r.POST("/copy", copyFileHandler)
    r.POST("/compress", compressFilesHandler)
    return r
}

func TestFileHandler(t *testing.T) {
    router := setupRouter()

    req, _ := http.NewRequest("GET", "/", nil)
    req.SetBasicAuth("admin", "password")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
    assert.Contains(t, w.Body.String(), "Files")
}

func TestUploadHandler(t *testing.T) {
    router := setupRouter()

    body := new(bytes.Buffer)
    writer := multipart.NewWriter(body)
    part, _ := writer.CreateFormFile("uploadfile", "test.txt")
    part.Write([]byte("This is a test file"))
    writer.Close()

    req, _ := http.NewRequest("POST", "/upload?dir=.", body)
    req.SetBasicAuth("admin", "password")
    req.Header.Set("Content-Type", writer.FormDataContentType())
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusSeeOther, w.Code)
    os.Remove("test.txt") // Clean up
}

func TestDownloadHandler(t *testing.T) {
    os.WriteFile("test.txt", []byte("This is a test file"), 0644)
    defer os.Remove("test.txt")

    router := setupRouter()

    req, _ := http.NewRequest("GET", "/download?file=test.txt", nil)
    req.SetBasicAuth("admin", "password")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteHandler(t *testing.T) {
    os.WriteFile("test.txt", []byte("This is a test file"), 0644)
    defer os.Remove("test.txt")

    router := setupRouter()

    req, _ := http.NewRequest("POST", "/delete?file=test.txt", nil)
    req.SetBasicAuth("admin", "password")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusSeeOther, w.Code)
}

func TestEditHandler(t *testing.T) {
    os.WriteFile("test.txt", []byte("This is a test file"), 0644)
    defer os.Remove("test.txt")

    router := setupRouter()

    req, _ := http.NewRequest("GET", "/edit?file=test.txt", nil)
    req.SetBasicAuth("admin", "password")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
}

func TestSaveHandler(t *testing.T) {
    os.WriteFile("test.txt", []byte("This is a test file"), 0644)
    defer os.Remove("test.txt")

    router := setupRouter()

    body := strings.NewReader("file=test.txt&content=Hello")
    req, _ := http.NewRequest("POST", "/save", body)
    req.SetBasicAuth("admin", "password")
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusSeeOther, w.Code)
}

func TestPreviewHandler(t *testing.T) {
    os.WriteFile("test.txt", []byte("This is a test file"), 0644)
    defer os.Remove("test.txt")

    router := setupRouter()

    req, _ := http.NewRequest("GET", "/preview?file=test.txt", nil)
    req.SetBasicAuth("admin", "password")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
    assert.Equal(t, "This is a test file", w.Body.String())
}

func TestChmodHandler(t *testing.T) {
    os.WriteFile("test.txt", []byte("This is a test file"), 0644)
    defer os.Remove("test.txt")

    router := setupRouter()

    body := strings.NewReader("file=test.txt&mode=0777")
    req, _ := http.NewRequest("POST", "/chmod", body)
    req.SetBasicAuth("admin", "password")
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusSeeOther, w.Code)
}

func TestCreateHandler(t *testing.T) {
    router := setupRouter()

    body := strings.NewReader("name=newfile.txt&type=file")
    req, _ := http.NewRequest("POST", "/create?dir=.", body)
    req.SetBasicAuth("admin", "password")
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusSeeOther, w.Code)
    os.Remove("newfile.txt") // Clean up
}

func TestCopyFileHandler(t *testing.T) {
    os.WriteFile("test.txt", []byte("This is a test file"), 0644)
    defer os.Remove("test.txt")
    defer os.Remove("copy_test.txt") // Clean up

    router := setupRouter()

    body := strings.NewReader("src=test.txt&dst=copy_test.txt")
    req, _ := http.NewRequest("POST", "/copy", body)
    req.SetBasicAuth("admin", "password")
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusSeeOther, w.Code)
}

func TestCompressFilesHandler(t *testing.T) {
    os.WriteFile("test1.txt", []byte("This is a test file 1"), 0644)
    os.WriteFile("test2.txt", []byte("This is a test file 2"), 0644)
    defer os.Remove("test1.txt")
    defer os.Remove("test2.txt")
    defer os.Remove("output.zip") // Clean up

    router := setupRouter()

    body := strings.NewReader("files=test1.txt&files=test2.txt&output=output.zip")
    req, _ := http.NewRequest("POST", "/compress", body)
    req.SetBasicAuth("admin", "password")
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
}