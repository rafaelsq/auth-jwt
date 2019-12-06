package auth

import (
	"fmt"
	"io"
	"io/ioutil"
	"sync"
	"time"

	"github.com/pascaldekloe/jwt"
)

const (
	AppleKeysURL = "https://appleid.apple.com/auth/keys"
)

type AppleJWT struct {
	sync.Mutex

	AUD        []string
	KeyTimeout time.Duration

	keysLastUpdated time.Time
	keys            jwt.KeyRegister
}

func (a *AppleJWT) Name() string {
	return "apple"
}

func (a *AppleJWT) ISS() string {
	return "https://appleid.apple.com"
}

func (a *AppleJWT) Keys() *jwt.KeyRegister {
	return &a.keys
}
func (a *AppleJWT) AUDs() []string {
	return a.AUD
}

func (a *AppleJWT) GetUser(j *jwt.Claims) (*User, error) {
	return &User{
		ID:    j.Subject,
		Email: j.Set["email"].(string),
	}, nil
}

func (a *AppleJWT) CheckKeys(fn func(url string) (io.ReadCloser, error)) error {
	a.Lock()
	defer a.Unlock()

	if time.Now().Add(-a.KeyTimeout).Before(a.keysLastUpdated) {
		return nil
	}

	body, err := fn(AppleKeysURL)
	if err != nil {
		return err
	}
	defer body.Close()

	b, err := ioutil.ReadAll(body)
	if err != nil {
		return fmt.Errorf("could not read response body; %v", err)
	}

	if _, err = a.keys.LoadJWK(b); err != nil {
		return fmt.Errorf("fail to parse body; %v", err)
	}

	a.keysLastUpdated = time.Now()
	return nil
}
