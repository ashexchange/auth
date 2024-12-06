package httpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ashexchange/auth"
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
	f := NewAuthMiddleware(&auths{},
		func(w http.ResponseWriter, r *http.Request, err error) {
			json.NewEncoder(w).Encode(map[string]any{"err": err.Error()})
		},
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", f.Auth()(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, fmt.Sprintf("hello: %v", GetID(r)))
	}))

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Beare token")
	mux.ServeHTTP(res, req)

	result, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", result)
}
