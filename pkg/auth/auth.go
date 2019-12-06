package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/pascaldekloe/jwt"
)

var (
	ErrInvalidProvider = errors.New("invalid provider")
	ErrInvalidAUD      = errors.New("invalid aud")
	ErrInvalidEXP      = errors.New("invalid exp")
	ErrInvalidISS      = errors.New("invalid iss")
	ErrInvalidKid      = errors.New("invalid kid")
	ErrExpired         = errors.New("expired")
)

var (
	once      sync.Once
	mutex     sync.Mutex
	providers map[string]Provider
)

type User struct {
	ID    string
	Name  string
	Email string
}

type Provider interface {
	Name() string
	AUDs() []string
	ISS() string
	Keys() *jwt.KeyRegister
	CheckKeys(fn func(url string) (io.ReadCloser, error)) error
	GetUser(*jwt.Claims) (*User, error)
}

func Register(provider ...Provider) {
	once.Do(func() {
		providers = make(map[string]Provider)
	})

	mutex.Lock()
	defer mutex.Unlock()

	for _, prov := range provider {
		providers[prov.Name()] = prov
	}
}

func Parse(providerName string, rawJWT []byte) (*User, error) {
	mutex.Lock()
	provider, exists := providers[providerName]

	if !exists {
		return nil, ErrInvalidProvider
	}
	mutex.Unlock()

	// update keys
	if err := provider.CheckKeys(RequestTimeout); err != nil {
		return nil, err
	}

	j, err := provider.Keys().Check(rawJWT)
	if err != nil {
		return nil, err
	}

	if !j.Valid(time.Now()) {
		return nil, ErrExpired
	}

	if j.Issuer != provider.ISS() {
		return nil, ErrInvalidISS
	}

	err = ErrInvalidAUD

	for _, aud := range j.Audiences {
		for _, key := range provider.AUDs() {
			if aud == key {
				err = nil
				break
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return provider.GetUser(j)
}

func RequestTimeout(url string) (io.ReadCloser, error) {
	var outErr error

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("could not create request; %v", err)
		}

		r, err := http.DefaultClient.Do(req)
		if errors.Is(err, context.DeadlineExceeded) {
			outErr = err
			continue
		}

		if err != nil {
			return nil, err
		}

		if r.StatusCode != http.StatusOK {
			outErr = fmt.Errorf("could not fetch; %v", r.StatusCode)
			time.Sleep(time.Second * time.Duration(i))
			continue
		}

		return r.Body, nil
	}

	return nil, outErr
}
