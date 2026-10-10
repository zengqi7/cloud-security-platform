package platform

import (
	"context"
	"errors"
	"log"
	"time"
)

type WorkRepository interface {
	Claim(context.Context) (Job, error)
	Finish(context.Context, Job, []Finding, error) error
}
type Worker struct {
	Repo    WorkRepository
	Scanner Scanner
}

func (w Worker) Once(ctx context.Context) (bool, error) {
	job, err := w.Repo.Claim(ctx)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	scanCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
	findings, scanErr := w.Scanner.Scan(scanCtx, job.Request)
	cancel()
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer finishCancel()
	if err := w.Repo.Finish(finishCtx, job, findings, scanErr); err != nil {
		return true, err
	}
	if scanErr != nil {
		log.Printf("scan_id=%s attempt=%d scanner_error=%v", job.ID, job.Attempts, scanErr)
	}
	return true, nil
}
func (w Worker) Run(ctx context.Context) error {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		worked, err := w.Once(ctx)
		if err != nil {
			log.Printf("scan worker: %v", err)
		}
		if worked && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
	}
}
