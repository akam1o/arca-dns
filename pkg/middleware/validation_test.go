package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type trackingBody struct {
	reader *strings.Reader
	read   bool
}

func newTrackingBody(body string) *trackingBody {
	return &trackingBody{reader: strings.NewReader(body)}
}

func (b *trackingBody) Read(p []byte) (int, error) {
	b.read = true
	return b.reader.Read(p)
}

func (b *trackingBody) Close() error {
	return nil
}

func TestRequestValidatorRejectsKnownOversizedBodyBeforeHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	called := false
	router := gin.New()
	router.Use(NewRequestValidatorWithMaxSize(4).Middleware())
	router.POST("/test", func(c *gin.Context) {
		called = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("12345"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.False(t, called)
}

func TestRequestValidatorDoesNotReadBodyBeforeHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	body := newTrackingBody("ok")
	readBeforeHandler := true

	router := gin.New()
	router.Use(NewRequestValidatorWithMaxSize(4).Middleware())
	router.POST("/test", func(c *gin.Context) {
		readBeforeHandler = body.read
		data, err := io.ReadAll(c.Request.Body)
		require.NoError(t, err)
		assert.Equal(t, "ok", string(data))
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", body)
	req.Body = body
	req.ContentLength = 2
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.False(t, readBeforeHandler)
	assert.True(t, body.read)
}

func TestRequestValidatorLimitsUnknownLengthBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(NewRequestValidatorWithMaxSize(4).Middleware())
	router.POST("/test", func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		require.NoError(t, err)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("12345"))
	req.ContentLength = -1
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}
