package main

import (
	"context"
	"log"
	"time"
)

type sendPush func(context.Context, Job) SendResult

func drainQueue(ctx context.Context, store *Store, send sendPush) error {
	for range 25 {
		if err := ctx.Err(); err != nil {
			return err
		}
		job, ok, err := store.Next()
		if err != nil || !ok {
			return err
		}
		result := send(ctx, job)
		if err := store.Finish(job, result); err != nil {
			return err
		}
	}
	return nil
}

func runWorker(ctx context.Context, store *Store, send sendPush) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if err := drainQueue(ctx, store, send); err != nil && ctx.Err() == nil {
			log.Print("delivery queue iteration failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func simulatePush(_ context.Context, job Job) SendResult {
	log.Printf("simulated provider acceptance: provider=%s environment=%s", job.Provider, job.Environment)
	return SendResult{Status: sendAccepted}
}
