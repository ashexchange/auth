package jwt

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/ashexchange/auth"
	"github.com/golang-jwt/jwt/v5"
)

type RegisteredClaims struct {
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience []string `json:"aud,omitempty"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt int64 `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore int64 `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt int64 `json:"iat,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`
}

func newNumericDate(sec int64) *jwt.NumericDate {
	if sec > 0 {
		return jwt.NewNumericDate(time.Unix(sec, 0))
	}
	return nil
}

// GetExpirationTime implements the Claims interface.
func (c RegisteredClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return newNumericDate(c.ExpiresAt), nil
}

// GetNotBefore implements the Claims interface.
func (c RegisteredClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return newNumericDate(c.NotBefore), nil
}

// GetIssuedAt implements the Claims interface.
func (c RegisteredClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return newNumericDate(c.IssuedAt), nil
}

// GetAudience implements the Claims interface.
func (c RegisteredClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}

// GetIssuer implements the Claims interface.
func (c RegisteredClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements the Claims interface.
func (c RegisteredClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

type CustomClaims struct {
	RegisteredClaims
	UID      int64  `json:"uid"`
	Platform string `json:"plf"`
}

var _ jwt.Claims = (*CustomClaims)(nil)

func (c CustomClaims) ID() int64 {
	return c.UID
}

const (
	SigningMethodHS256 = "HS256"
	SigningMethodHS384 = "HS384"
	SigningMethodHS512 = "HS521"
)

type Codec struct {
	keyFunc jwt.Keyfunc
	method  string
}

type CodecOption func(o *Codec)

func WithSigningMethod(method string) CodecOption {
	return func(o *Codec) {
		o.method = method
	}
}

func NewCodec(kf jwt.Keyfunc, opts ...CodecOption) *Codec {
	c := &Codec{
		keyFunc: kf,
		method:  "HS256",
	}

	for _, o := range opts {
		o(c)
	}

	return c
}

func NewCodecWithKey(key []byte, opts ...CodecOption) *Codec {
	return NewCodec(defaultKeyFunc(key), opts...)
}

func NewCodecWithBase64String(key string, opts ...CodecOption) *Codec {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		panic(err)
	}

	return NewCodecWithKey(b, opts...)
}

func (c *Codec) Decode(tokenString string) (*CustomClaims, error) {
	claims := new(CustomClaims)
	token, err := jwt.ParseWithClaims(tokenString, claims, c.keyFunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, auth.ErrTokenExpired
		}

		return nil, err
	}

	if !token.Valid {
		return nil, auth.ErrInvalidToken
	}

	return claims, nil
}

func (c *Codec) Encode(claims *CustomClaims) (string, error) {
	if claims == nil {
		return "", errors.New("claims is nil")
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(c.method), claims)

	key, err := c.keyFunc(token)
	if err != nil {
		return "", err
	}

	return token.SignedString(key)
}

func defaultKeyFunc(key []byte) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}
}
