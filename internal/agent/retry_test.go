package agent

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestRetryableReportStatusIsLimitedToTransientFailures(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		if !retryableReportStatus(status) {
			t.Fatalf("HTTP %d should be retried", status)
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict} {
		if retryableReportStatus(status) {
			t.Fatalf("HTTP %d must not be retried", status)
		}
	}
}

func TestReportRetryWaitHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitForReportRetry(ctx, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
