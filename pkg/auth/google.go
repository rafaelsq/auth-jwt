package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pascaldekloe/jwt"
)

const (
	GoogleCertsURL = "https://www.googleapis.com/oauth2/v1/certs"
)

type GoogleJWT struct {
	sync.Mutex

	AUD        []string
	KeyTimeout time.Duration

	keysLastUpdated time.Time
	keys            jwt.KeyRegister
}

func (g *GoogleJWT) Name() string {
	return "google"
}
func (g *GoogleJWT) ISS() string {
	return "https://accounts.google.com"
}

func (g *GoogleJWT) Keys() *jwt.KeyRegister {
	return &g.keys
}

func (g *GoogleJWT) AUDs() []string {
	return g.AUD
}

func (g *GoogleJWT) GetUser(j *jwt.Claims) (*User, error) {
	return &User{
		ID:    j.Subject,
		Name:  j.Set["name"].(string),
		Email: j.Set["email"].(string),
	}, nil
}

func (g *GoogleJWT) CheckKeys(fn func(url string) (io.ReadCloser, error)) error {
	g.Lock()
	defer g.Unlock()

	if time.Now().Add(-g.KeyTimeout).Before(g.keysLastUpdated) {
		return nil
	}

	body, err := fn(GoogleCertsURL)
	if err != nil {
		return err
	}
	defer body.Close()

	var keys map[string]string

	if err := json.NewDecoder(body).Decode(&keys); err != nil {
		return fmt.Errorf("could not parse response body; %v", err)
	}

	for _, key := range keys {
		if _, err := g.keys.LoadPEM([]byte(key), nil); err != nil {
			return fmt.Errorf("could not read PEM key; %v", err)
		}
	}

	g.keysLastUpdated = time.Now()
	return nil
}
