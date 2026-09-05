// Package browserreview owns HAVEN's encrypted, owner-reported browser-site
// classifications. It deliberately stores no cookie names, values, tokens,
// paths, or browser-history contents.
package browserreview

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/storage"
)

const maximumReviewsPerDevice = 4096

const (
	StateSignedInKeep       = "signed-in-keep"
	StateRecognizedOrdinary = "recognized-ordinary"
	StateClearCandidate     = "clear-candidate"
	StateReviewLater        = "review-later"
)

var (
	ErrInvalidReview = errors.New("browser site review is invalid")
	ErrReviewLimit   = errors.New("browser site review limit reached")
	fingerprintRE    = regexp.MustCompile(`^[0-9a-f]{24}$`)
	domainRE         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type ReviewKey struct {
	DeviceID           string `json:"deviceId"`
	BrowserID          string `json:"browserId"`
	ProfileFingerprint string `json:"profileFingerprint"`
	Domain             string `json:"domain"`
}

type ReviewInput struct {
	ReviewKey
	State string `json:"state"`
}

type Review struct {
	ReviewInput
	ReviewedAt time.Time `json:"reviewedAt"`
}

type storedReview struct {
	BrowserID          string `json:"browserId"`
	ProfileFingerprint string `json:"profileFingerprint"`
	Domain             string `json:"domain"`
	State              string `json:"state"`
}

type Service struct {
	store *storage.Store
	key   []byte
}

func New(store *storage.Store, keyPath string) (*Service, error) {
	if store == nil {
		return nil, errors.New("browser site review storage is required")
	}
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("configure browser site review encryption: %w", err)
	}
	return &Service{store: store, key: key}, nil
}

func (service *Service) List(ctx context.Context, deviceID string) ([]Review, error) {
	if !validDeviceID(deviceID) {
		return nil, ErrInvalidReview
	}
	records, err := service.store.ListEncryptedBrowserSiteReviews(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	reviews := make([]Review, 0, len(records))
	for _, record := range records {
		plain, err := service.open(record.ID, record.DeviceID, record.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("open browser site review %q: %w", record.ID, err)
		}
		var stored storedReview
		if err := json.Unmarshal(plain, &stored); err != nil {
			return nil, errors.New("stored browser site review is invalid")
		}
		input, err := NormalizeReviewInput(ReviewInput{ReviewKey: ReviewKey{DeviceID: record.DeviceID, BrowserID: stored.BrowserID, ProfileFingerprint: stored.ProfileFingerprint, Domain: stored.Domain}, State: stored.State})
		if err != nil || service.reviewID(input.ReviewKey) != record.ID {
			return nil, errors.New("stored browser site review is invalid")
		}
		reviews = append(reviews, Review{ReviewInput: input, ReviewedAt: record.UpdatedAt})
	}
	sort.SliceStable(reviews, func(left, right int) bool {
		if reviews[left].ProfileFingerprint != reviews[right].ProfileFingerprint {
			return reviews[left].ProfileFingerprint < reviews[right].ProfileFingerprint
		}
		return reviews[left].Domain < reviews[right].Domain
	})
	return reviews, nil
}

func (service *Service) Save(ctx context.Context, input ReviewInput, now time.Time) (Review, error) {
	input, err := NormalizeReviewInput(input)
	if err != nil {
		return Review{}, err
	}
	now = now.UTC()
	id := service.reviewID(input.ReviewKey)
	createdAt := now
	if existing, err := service.store.EncryptedBrowserSiteReview(ctx, input.DeviceID, id); err == nil {
		createdAt = existing.CreatedAt
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Review{}, err
	} else {
		records, err := service.store.ListEncryptedBrowserSiteReviews(ctx, input.DeviceID)
		if err != nil {
			return Review{}, err
		}
		if len(records) >= maximumReviewsPerDevice {
			return Review{}, ErrReviewLimit
		}
	}
	plain, err := json.Marshal(storedReview{BrowserID: input.BrowserID, ProfileFingerprint: input.ProfileFingerprint, Domain: input.Domain, State: input.State})
	if err != nil {
		return Review{}, err
	}
	ciphertext, err := service.seal(id, input.DeviceID, plain)
	if err != nil {
		return Review{}, err
	}
	if err := service.store.SaveEncryptedBrowserSiteReview(ctx, storage.EncryptedBrowserSiteReview{ID: id, DeviceID: input.DeviceID, Ciphertext: ciphertext, CreatedAt: createdAt, UpdatedAt: now}); err != nil {
		return Review{}, err
	}
	return Review{ReviewInput: input, ReviewedAt: now}, nil
}

func (service *Service) Remove(ctx context.Context, key ReviewKey) error {
	key, err := NormalizeReviewKey(key)
	if err != nil {
		return err
	}
	return service.store.DeleteBrowserSiteReview(ctx, key.DeviceID, service.reviewID(key))
}

func NormalizeReviewInput(input ReviewInput) (ReviewInput, error) {
	key, err := NormalizeReviewKey(input.ReviewKey)
	if err != nil {
		return ReviewInput{}, err
	}
	input.ReviewKey = key
	input.State = strings.TrimSpace(input.State)
	if input.State != StateSignedInKeep && input.State != StateRecognizedOrdinary && input.State != StateClearCandidate && input.State != StateReviewLater {
		return ReviewInput{}, ErrInvalidReview
	}
	return input, nil
}

func NormalizeReviewKey(key ReviewKey) (ReviewKey, error) {
	key.DeviceID = strings.TrimSpace(key.DeviceID)
	key.BrowserID = strings.ToLower(strings.TrimSpace(key.BrowserID))
	key.ProfileFingerprint = strings.ToLower(strings.TrimSpace(key.ProfileFingerprint))
	key.Domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(key.Domain)), ".")
	if !validDeviceID(key.DeviceID) || key.BrowserID != "chrome" || !fingerprintRE.MatchString(key.ProfileFingerprint) || !validDomain(key.Domain) {
		return ReviewKey{}, ErrInvalidReview
	}
	return key, nil
}

func validDeviceID(value string) bool {
	return value != "" && len(value) <= 120 && !strings.ContainsAny(value, "/?#\\\r\n\t")
}

func validDomain(value string) bool {
	return domainRE.MatchString(value) && !strings.Contains(value, "..")
}

func (service *Service) reviewID(key ReviewKey) string {
	mac := hmac.New(sha256.New, service.derivedKey("identity-v1"))
	_, _ = mac.Write([]byte(key.DeviceID + "\x00" + key.BrowserID + "\x00" + key.ProfileFingerprint + "\x00" + key.Domain))
	return "brv_" + hex.EncodeToString(mac.Sum(nil)[:16])
}

func (service *Service) seal(id, deviceID string, plain []byte) ([]byte, error) {
	gcm, err := service.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte("HAVEN browser site review v1:"+deviceID+":"+id)), nil
}

func (service *Service) open(id, deviceID string, value []byte) ([]byte, error) {
	gcm, err := service.gcm()
	if err != nil {
		return nil, err
	}
	if len(value) < gcm.NonceSize() {
		return nil, errors.New("stored browser site review is invalid")
	}
	plain, err := gcm.Open(nil, value[:gcm.NonceSize()], value[gcm.NonceSize():], []byte("HAVEN browser site review v1:"+deviceID+":"+id))
	if err != nil {
		return nil, errors.New("stored browser site review could not be decrypted")
	}
	return plain, nil
}

func (service *Service) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(service.derivedKey("encryption-v1"))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (service *Service) derivedKey(purpose string) []byte {
	mac := hmac.New(sha256.New, service.key)
	_, _ = mac.Write([]byte("HAVEN browser site review " + purpose))
	return mac.Sum(nil)
}

func loadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("browser site review key path is required")
	}
	if value, err := os.ReadFile(path); err == nil {
		if len(value) != 32 {
			return nil, errors.New("browser site review encryption key has an invalid length")
		}
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			value, err := os.ReadFile(path)
			if err != nil || len(value) != 32 {
				return nil, errors.New("browser site review encryption key has an invalid length")
			}
			return value, nil
		}
		return nil, err
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return value, nil
}
