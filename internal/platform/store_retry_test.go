package platform

import (
	"context"
	"errors"
	"testing"

	mysqlerr "github.com/go-sql-driver/mysql"
)

func TestRetryTransactionRetriesOnlyTransientMySQLErrors(t *testing.T) {
	attempts := 0
	err := retryTransaction(context.Background(), func() error {
		attempts++
		if attempts < transactionRetryLimit {
			return &mysqlerr.MySQLError{Number: 1213, Message: "deadlock"}
		}
		return nil
	})
	if err != nil || attempts != transactionRetryLimit {
		t.Fatalf("retry result: attempts=%d err=%v", attempts, err)
	}

	nonRetryable := errors.New("permanent")
	attempts = 0
	err = retryTransaction(context.Background(), func() error {
		attempts++
		return nonRetryable
	})
	if !errors.Is(err, nonRetryable) || attempts != 1 {
		t.Fatalf("non-retryable result: attempts=%d err=%v", attempts, err)
	}
}

func TestRetryTransactionHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := retryTransaction(ctx, func() error {
		attempts++
		cancel()
		return &mysqlerr.MySQLError{Number: 1205, Message: "lock wait timeout"}
	})
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("canceled result: attempts=%d err=%v", attempts, err)
	}
}
