package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	token := os.Getenv("RELAY_OPERATOR_TOKEN")
	if decoded, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(decoded) < 32 {
		return errors.New("RELAY_OPERATOR_TOKEN must be an unpadded base64url credential of at least 32 bytes")
	}
	path := os.Getenv("RELAY_STATE_PATH")
	if path == "" {
		path = "relay-state.json"
	}
	addr := os.Getenv("RELAY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	mode := os.Getenv("RELAY_MODE")
	send, err := resolveSendPush(mode, os.Getenv)
	if err != nil {
		return err
	}
	var store *Store
	if mode == "staging" || mode == "production" {
		key := os.Getenv("RELAY_STATE_KEY")
		if key == token {
			return errors.New("RELAY_STATE_KEY and RELAY_OPERATOR_TOKEN must be different")
		}
		store, err = openEncryptedStore(path, time.Now, key, mode)
	} else {
		store, err = OpenStore(path, time.Now)
	}
	if err != nil {
		return err
	}
	// Off by default: NodeScope re-registers on unknown_installation only
	// from the release that added it, so enable this after that ships.
	if raw := os.Getenv("RELAY_INSTALLATION_IDLE_DAYS"); raw != "" {
		days, err := strconv.Atoi(raw)
		if err != nil || days < 0 || days > 3650 {
			return errors.New("RELAY_INSTALLATION_IDLE_DAYS must be a whole number of days from 0 to 3650")
		}
		store.SetInstallationIdle(time.Duration(days) * 24 * time.Hour)
	}
	var fetchProof enrollmentProofFetcher
	var publicOrigin string
	switch os.Getenv("RELAY_SELF_ENROLL") {
	case "true":
		fetchProof = fetchPublicEnrollmentProof
		if publicOrigin, err = relayPublicOrigin(os.Getenv("RELAY_PUBLIC_ORIGIN")); err != nil {
			return err
		}
	case "", "false":
	default:
		return errors.New("RELAY_SELF_ENROLL must be true or false")
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           newRelayHandler(store, token, fetchProof, publicOrigin),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		runWorker(ctx, store, send)
	}()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.ListenAndServe()
	}()
	if mode == "" {
		mode = "simulate"
	}
	log.Printf("NodeScope relay listening on %s (mode=%s)", addr, mode)
	select {
	case err = <-serverDone:
		stop()
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if server.Shutdown(shutdown) != nil {
			_ = server.Close()
		}
		cancel()
		err = <-serverDone
	}
	<-workerDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
