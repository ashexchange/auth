package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ashexchange/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type authenticator struct {
	rc         redis.UniversalClient
	codec      *Codec
	expiration time.Duration
}

var _ auth.Authenticator = (*authenticator)(nil)

type Option interface {
	apply(a *authenticator)
}

type optionFunc func(*authenticator)

func (f optionFunc) apply(a *authenticator) {
	f(a)
}

func WithKeyFunc(f jwt.Keyfunc, opts ...CodecOption) Option {
	return optionFunc(func(a *authenticator) {
		a.codec = NewCodec(f, opts...)
	})
}

func WithKey(key []byte, opts ...CodecOption) Option {
	return optionFunc(func(a *authenticator) {
		a.codec = NewCodecWithKey(key, opts...)
	})
}

func WithBase64Key(key string, opts ...CodecOption) Option {
	return optionFunc(func(a *authenticator) {
		a.codec = NewCodecWithBase64String(key, opts...)
	})
}

func Expiration(d time.Duration) Option {
	return optionFunc(func(a *authenticator) {
		if d > 0 {
			a.expiration = d
		}
	})
}

func NewAuthorizator(rc redis.UniversalClient, opts ...Option) (auth.Authenticator, error) {
	a := &authenticator{rc: rc, expiration: 24 * time.Hour}
	for _, o := range opts {
		o.apply(a)
	}

	if a.codec == nil {
		return nil, errors.New("missing jwt codec")
	}

	return a, nil
}

func (a *authenticator) Auth(ctx context.Context, token string) (auth.Claims, error) {
	if token == "" {
		return nil, auth.ErrUnauthorized
	}

	claims, err := a.codec.Decode(token)
	if err != nil {
		return nil, err
	}

	if err = a.renewToken(ctx, token, claims.UID, claims.Platform); err != nil {
		return nil, err
	}

	return &CustomClaims{UID: claims.UID}, nil
}

func (a *authenticator) renewToken(ctx context.Context, token string, userId int64, platform string) error {
	key := fmt.Sprintf("account:token:%d", userId)
	result, err := a.rc.HGet(ctx, key, platform).Result()
	if err != nil {
		return auth.ErrTokenExpired
	}

	if len(result) == 0 || result != token {
		return auth.ErrTokenExpired
	}

	a.rc.Expire(ctx, key, a.expiration)

	return nil
}
