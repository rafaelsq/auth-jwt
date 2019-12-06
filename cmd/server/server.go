package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/go-chi/chi"
	"github.com/rafaelsq/auth-jwt/pkg/auth"
)

func main() {
	var port = flag.Int("port", 2000, "")

	flag.Parse()

	r := chi.NewRouter()

	auth.Register(&auth.AppleJWT{
		KeyTimeout: time.Second * 10,
		AUD:        []string{"com.rafalquintela.SingInApple"},
	}, &auth.GoogleJWT{
		KeyTimeout: time.Second * 10,
		AUD:        []string{"000000000000-ffffffffffffffffffffffffffffffff.apps.googleusercontent.com"},
	})

	r.Get("/{provider:[a-z]+}", func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.Parse(chi.URLParam(r, "provider"), []byte(r.FormValue("jwt")))
		if err != nil {
			fmt.Fprintf(w, "err; %v", err)
		} else {
			fmt.Fprintf(w, "ok; %#v", user)
		}
	})

	// graceful shutdown
	srv := http.Server{Addr: fmt.Sprintf(":%d", *port), Handler: r}

	c := make(chan os.Signal, 1)
	iddleConnections := make(chan struct{})

	signal.Notify(c, os.Interrupt)

	go func() {
		<-c
		// sig is a ^C, handle it
		log.Println("shutting down..")

		// create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// start http shutdown
		if err := srv.Shutdown(ctx); err != nil {
			log.Println("shutdown error", err)
		}

		close(iddleConnections)
	}()

	log.Printf("Listening on :%d\n", *port)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

	log.Println("waiting iddle connections...")
	<-iddleConnections
	log.Println("done, bye!")
}
