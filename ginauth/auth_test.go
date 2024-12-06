package ginauth

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ashexchange/auth"
	"github.com/gin-gonic/gin"
)

type (
	auths  struct{}
	claims struct{}
)

func (c *claims) ID() int64 {
	return 100
}

func (a *auths) Auth(ctx context.Context, token string) (auth.Claims, error) {
	return &claims{}, nil
}

func TestAuth(t *testing.T) {
	r := gin.New()
	r.ContextWithFallback = true
	r.GET("/",
		NewAuthMiddleware(&auths{}, func(c *gin.Context, err error) {
			c.JSON(400, map[string]any{"err": err.Error()})
		}).Auth(),
		func(c *gin.Context) {
			c.String(200, fmt.Sprintf("hello: %v", GetID(c)))
		},
	)

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// req.Header.Set("Authorization", "Beare token")
	r.ServeHTTP(res, req)

	result, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", result)
}
