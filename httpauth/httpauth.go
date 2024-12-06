package httpauth

import (
	"net/http"

	"github.com/ashexchange/auth"
)

var HeaderName = "Authorization"

type Middleware = func(next http.HandlerFunc) http.HandlerFunc

type ErrHandler func(w http.ResponseWriter, r *http.Request, err error)

type AuthMiddleware struct {
	auth       auth.Authenticator
	errHandler ErrHandler
	getToken   func(r *http.Request) string
}

type Option func(*AuthMiddleware)

func WithGetToken(fn func(r *http.Request) string) Option {
	return func(am *AuthMiddleware) {
		am.getToken = fn
	}
}

func NewAuthMiddleware(auth auth.Authenticator, eh ErrHandler, opts ...Option) *AuthMiddleware {
	if auth == nil || eh == nil {
		panic("auth and errHandler cannot be nil")
	}

	am := &AuthMiddleware{
		auth:       auth,
		errHandler: eh,
		getToken:   getToken,
	}
	for _, o := range opts {
		o(am)
	}

	return am
}

const bearerLength = len("Bearer")

func getToken(r *http.Request) string {
	token := r.Header.Get(HeaderName)
	if token != "" && len(token) > 6 {
		return token[bearerLength:]
	}
	return ""
}

func (a *AuthMiddleware) Auth(ignoreable ...bool) func(next http.HandlerFunc) http.HandlerFunc {
	ignore := false
	if len(ignoreable) > 0 {
		ignore = ignoreable[0]
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := a.getToken(r)
			if ignore && token == "" {
				next(w, r)
				return
			}

			ctx := r.Context()
			claims, err := a.auth.Auth(ctx, token)
			if err != nil {
				a.errHandler(w, r, err)
				return
			}

			next(w, r.WithContext(auth.WithClaims(ctx, claims)))
		}
	}
}

func GetID(r *http.Request) int64 {
	return auth.GetID(r.Context())
}
