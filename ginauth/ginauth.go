package ginauth

import (
	"github.com/ashexchange/auth"
	"github.com/gin-gonic/gin"
)

var HeaderName = "Authorization"

type ErrHandler func(c *gin.Context, err error)

type AuthMiddleware struct {
	auth       auth.Authenticator
	errHandler ErrHandler
	getToken   func(c *gin.Context) string
}

type Option func(*AuthMiddleware)

func WithGetToken(fn func(c *gin.Context) string) Option {
	return func(am *AuthMiddleware) {
		am.getToken = fn
	}
}

const bearerLength = len("Bearer")

func getToken(c *gin.Context) string {
	token := c.GetHeader(HeaderName)
	if token != "" && len(token) > 6 {
		return token[bearerLength:]
	}
	return ""
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

func (a *AuthMiddleware) Auth(ignoreable ...bool) func(c *gin.Context) {
	ignore := false
	if len(ignoreable) > 0 {
		ignore = ignoreable[0]
	}

	return func(c *gin.Context) {
		token := a.getToken(c)
		if ignore && token == "" {
			return
		}

		ctx := c.Request.Context()
		claims, err := a.auth.Auth(ctx, token)
		if err != nil {
			a.errHandler(c, err)
			c.Abort()
			return
		}

		c.Request = c.Request.WithContext(auth.WithClaims(ctx, claims))
	}
}

func GetID(c *gin.Context) int64 {
	return auth.GetID(c.Request.Context())
}
