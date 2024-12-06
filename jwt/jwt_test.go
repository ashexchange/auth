package jwt

import (
	"reflect"
	"testing"
	"time"
)

func TestJwt(t *testing.T) {
	codec := NewCodecWithKey([]byte("helloworld"))
	claims := &CustomClaims{RegisteredClaims: RegisteredClaims{IssuedAt: time.Now().Unix()}, UID: 100, Platform: "ios"}

	s, err := codec.Encode(claims)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("token: %s", s)

	c, err := codec.Decode(s)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(c, claims) {
		t.Errorf("not eq")
	}
}
