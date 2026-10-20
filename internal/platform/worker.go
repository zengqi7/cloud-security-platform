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
	Health  *WorkerHealth
}

func (w Worker) Once(ctx context.Context) (bool, error) {
	claimCtx, claimCancel := context.WithTimeout(ctx, 5*time.Second)
	job, err := w.Repo.Claim(claimCtx)
	claimCancel()
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	scanCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
	var findings []Finding
	var scanErr error
	var result ScanResult
	if scanner, ok := w.Scanner.(ToolScanner); ok {
		loader, ok := w.Repo.(interface {
			LoadPolicy(context.Context, string, string) (PolicyBundle, error)
		})
		if !ok {
			scanErr = errors.New("policy repository unavailable")
		} else {
			bundle, err := loader.LoadPolicy(scanCtx, job.Tenant, job.PolicyDigest)
			if err != nil {
				scanErr = err
			} else {
				trust := TrustPolicy{Mode: "disabled"}
				if job.Trust != nil {
					trust = *job.Trust
				}
				registryCtx, cleanup, err := scanner.registryContext(scanCtx, job.Tenant, job.Request)
				if err != nil {
					scanErr = err
				} else {
					result, scanErr = scanner.scanEvidence(registryCtx, job.Request, bundle, trust)
				}
				cleanup()
				findings = result.Findings
			}
		}
	} else {
		findings, scanErr = w.Scanner.Scan(scanCtx, job.Request)
		result.Findings = findings
	}
	cancel()
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer finishCancel()
	var finishErr error
	if repo, ok := w.Repo.(interface {
		FinishEvidence(context.Context, Job, ScanResult, error) error
	}); ok {
		finishErr = repo.FinishEvidence(finishCtx, job, result, scanErr)
	} else {
		finishErr = w.Repo.Finish(finishCtx, job, findings, scanErr)
	}
	if finishErr != nil {
		return true, finishErr
	}
	if scanErr != nil {
		log.Printf("scan_id=%s attempt=%d scanner_error=%v", job.ID, job.Attempts, scanErr)
	}
	return true, nil
}
func (w Worker) Run(ctx context.Context) error {
	if w.Health != nil {
		w.Health.Progress()
		w.Health.ready.Store(true)
		defer w.Health.ready.Store(false)
	}
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if w.Health != nil {
			w.Health.Progress()
		}
		if repo, ok := w.Repo.(interface {
			EnqueueRescan(context.Context) (bool, error)
		}); ok {
			scheduleCtx, scheduleCancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := repo.EnqueueRescan(scheduleCtx)
			scheduleCancel()
			if err != nil {
				log.Printf("rescan scheduler: %v", err)
			}
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
