package auth

import (
	"context"
	"errors"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrUnauthorized = errors.New("unauthorized")
	ErrTokenExpired = errors.New("token expired")
)

type Authenticator interface {
	Auth(ctx context.Context, token string) (Claims, error)
}

type Claims interface {
	ID() int64
}

type claimsKey struct{}

func WithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

func FromContext(ctx context.Context) Claims {
	claims, _ := ctx.Value(claimsKey{}).(Claims)
	return claims
}

func GetID(ctx context.Context) int64 {
	if claims := FromContext(ctx); claims != nil {
		return claims.ID()
	}
	return 0
}
