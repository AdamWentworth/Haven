package authn

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AdamWentworth/haven/internal/storage"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	SessionCookie = "haven_session"
	CSRFCookie    = "haven_csrf"
)

var (
	ErrNotConfigured     = errors.New("passkey authentication has not been configured")
	ErrAlreadyConfigured = errors.New("passkey authentication is already configured")
	ErrCeremonyInvalid   = errors.New("authentication ceremony is invalid or expired")
	ErrSessionInvalid    = errors.New("authentication session is invalid or expired")
	ErrCSRFInvalid       = errors.New("anti-forgery token is invalid")
)

type Service struct {
	store         *storage.Store
	webAuthn      *webauthn.WebAuthn
	key           []byte
	origin        string
	secureCookies bool

	mutex      sync.Mutex
	ceremonies map[string]ceremony
	attempts   map[string]attemptWindow
}

type ceremony struct {
	kind      string
	session   webauthn.SessionData
	tokenHash []byte
	expiresAt time.Time
}

type attemptWindow struct {
	startedAt time.Time
	count     int
}

type User struct {
	record      storage.AuthUserRecord
	credentials []webauthn.Credential
}

func (user *User) WebAuthnID() []byte                         { return user.record.WebAuthnID }
func (user *User) WebAuthnName() string                       { return user.record.Name }
func (user *User) WebAuthnDisplayName() string                { return user.record.DisplayName }
func (user *User) WebAuthnCredentials() []webauthn.Credential { return user.credentials }

type CeremonyResponse struct {
	CeremonyID string `json:"ceremonyId"`
	PublicKey  any    `json:"publicKey"`
}

type Session struct {
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

func New(store *storage.Store, keyPath, origin string) (*Service, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("HAVEN_PUBLIC_ORIGIN must be an origin without a path, query, or fragment")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "localhost") {
		return nil, errors.New("HAVEN_PUBLIC_ORIGIN must use HTTPS, except http://localhost is allowed for local development")
	}
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	instance, err := webauthn.New(&webauthn.Config{
		RPID:          parsed.Hostname(),
		RPDisplayName: "HAVEN Personal Security Observatory",
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure passkey authentication: %w", err)
	}
	return &Service{store: store, webAuthn: instance, key: key, origin: origin, secureCookies: parsed.Scheme == "https", ceremonies: map[string]ceremony{}, attempts: map[string]attemptWindow{}}, nil
}

func (service *Service) Origin() string      { return service.origin }
func (service *Service) SecureCookies() bool { return service.secureCookies }

func CreateBootstrap(ctx context.Context, store *storage.Store, validFor time.Duration, now time.Time) (string, error) {
	configured, err := store.AuthConfigured(ctx)
	if err != nil {
		return "", err
	}
	if configured {
		return "", ErrAlreadyConfigured
	}
	if _, err := store.EnsureAuthUser(ctx, now); err != nil {
		return "", err
	}
	token, err := randomToken(24)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(token))
	if err := store.CreateAuthBootstrap(ctx, digest[:], now.Add(validFor), now); err != nil {
		return "", err
	}
	return token, nil
}

func (service *Service) Configured(ctx context.Context) (bool, error) {
	return service.store.AuthConfigured(ctx)
}

func (service *Service) AllowAttempt(key string, now time.Time) bool {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	window := service.attempts[key]
	if window.startedAt.IsZero() || now.Sub(window.startedAt) >= time.Minute {
		service.attempts[key] = attemptWindow{startedAt: now, count: 1}
		return true
	}
	if window.count >= 10 {
		return false
	}
	window.count++
	service.attempts[key] = window
	return true
}

func (service *Service) BeginRegistration(ctx context.Context, bootstrapCode string, now time.Time) (CeremonyResponse, error) {
	configured, err := service.store.AuthConfigured(ctx)
	if err != nil {
		return CeremonyResponse{}, err
	}
	if configured {
		return CeremonyResponse{}, ErrAlreadyConfigured
	}
	tokenHash := sha256.Sum256([]byte(strings.TrimSpace(bootstrapCode)))
	valid, err := service.store.BootstrapValid(ctx, tokenHash[:], now)
	if err != nil {
		return CeremonyResponse{}, err
	}
	if !valid {
		return CeremonyResponse{}, storage.ErrBootstrapInvalid
	}
	user, err := service.loadUser(ctx)
	if err != nil {
		return CeremonyResponse{}, err
	}
	creation, session, err := service.webAuthn.BeginRegistration(user)
	if err != nil {
		return CeremonyResponse{}, err
	}
	ceremonyID, err := service.remember("registration", *session, tokenHash[:], now)
	if err != nil {
		return CeremonyResponse{}, err
	}
	return CeremonyResponse{CeremonyID: ceremonyID, PublicKey: creation.Response}, nil
}

func (service *Service) FinishRegistration(ctx context.Context, ceremonyID string, request *http.Request, now time.Time) (Session, error) {
	stored, err := service.take(ceremonyID, "registration", now)
	if err != nil {
		return Session{}, err
	}
	user, err := service.loadUser(ctx)
	if err != nil {
		return Session{}, err
	}
	credential, err := service.webAuthn.FinishRegistration(user, stored.session, request)
	if err != nil {
		return Session{}, err
	}
	encrypted, err := service.encryptCredential(*credential)
	if err != nil {
		return Session{}, err
	}
	if err := service.store.CompleteAuthBootstrap(ctx, stored.tokenHash, credential.ID, encrypted, now); err != nil {
		return Session{}, err
	}
	_ = service.store.AppendAudit(ctx, storage.AuditEvent{Actor: "owner", Action: "auth.passkey.register", Target: "owner", Outcome: "succeeded", Detail: "A new HAVEN passkey was registered.", OccurredAt: now})
	return service.NewSession(ctx, now)
}

func (service *Service) BeginLogin(ctx context.Context, now time.Time) (CeremonyResponse, error) {
	configured, err := service.store.AuthConfigured(ctx)
	if err != nil {
		return CeremonyResponse{}, err
	}
	if !configured {
		return CeremonyResponse{}, ErrNotConfigured
	}
	assertion, session, err := service.webAuthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return CeremonyResponse{}, err
	}
	ceremonyID, err := service.remember("login", *session, nil, now)
	if err != nil {
		return CeremonyResponse{}, err
	}
	return CeremonyResponse{CeremonyID: ceremonyID, PublicKey: assertion.Response}, nil
}

func (service *Service) FinishLogin(ctx context.Context, ceremonyID string, request *http.Request, now time.Time) (Session, error) {
	stored, err := service.take(ceremonyID, "login", now)
	if err != nil {
		return Session{}, err
	}
	var matched *User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		user, err := service.loadUser(ctx)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(user.WebAuthnID(), userHandle) != 1 {
			return nil, errors.New("unknown passkey owner")
		}
		found := false
		for _, credential := range user.credentials {
			if subtle.ConstantTimeCompare(credential.ID, rawID) == 1 {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("unknown passkey")
		}
		matched = user
		return user, nil
	}
	_, credential, err := service.webAuthn.FinishPasskeyLogin(handler, stored.session, request)
	if err != nil {
		return Session{}, err
	}
	if matched == nil {
		return Session{}, errors.New("passkey owner could not be resolved")
	}
	encrypted, err := service.encryptCredential(*credential)
	if err != nil {
		return Session{}, err
	}
	if err := service.store.UpdateAuthCredential(ctx, credential.ID, encrypted, now); err != nil {
		return Session{}, err
	}
	_ = service.store.AppendAudit(ctx, storage.AuditEvent{Actor: "owner", Action: "auth.login", Target: "owner", Outcome: "succeeded", Detail: "Passkey sign-in succeeded.", OccurredAt: now})
	return service.NewSession(ctx, now)
}

func (service *Service) NewSession(ctx context.Context, now time.Time) (Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := sha256.Sum256([]byte(csrf))
	expires := now.Add(12 * time.Hour)
	if err := service.store.CreateAuthSession(ctx, tokenHash[:], csrfHash[:], expires, now); err != nil {
		return Session{}, err
	}
	return Session{Token: token, CSRFToken: csrf, ExpiresAt: expires}, nil
}

func (service *Service) ValidateSession(ctx context.Context, token string, now time.Time) (bool, error) {
	if token == "" {
		return false, nil
	}
	digest := sha256.Sum256([]byte(token))
	return service.store.ValidateAuthSession(ctx, digest[:], nil, now)
}

func (service *Service) ValidateCSRF(ctx context.Context, sessionToken, cookieToken, headerToken string, now time.Time) error {
	if cookieToken == "" || headerToken == "" || subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
		return ErrCSRFInvalid
	}
	sessionHash := sha256.Sum256([]byte(sessionToken))
	csrfHash := sha256.Sum256([]byte(headerToken))
	valid, err := service.store.ValidateAuthSession(ctx, sessionHash[:], csrfHash[:], now)
	if err != nil {
		return err
	}
	if !valid {
		return ErrCSRFInvalid
	}
	return nil
}

func (service *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	return service.store.DeleteAuthSession(ctx, digest[:])
}

func (service *Service) loadUser(ctx context.Context) (*User, error) {
	record, err := service.store.LoadAuthUser(ctx)
	if err != nil {
		return nil, err
	}
	stored, err := service.store.AuthCredentials(ctx)
	if err != nil {
		return nil, err
	}
	credentials := make([]webauthn.Credential, 0, len(stored))
	for _, item := range stored {
		credential, err := service.decryptCredential(item.EncryptedCredential)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return &User{record: record, credentials: credentials}, nil
}

func (service *Service) remember(kind string, session webauthn.SessionData, tokenHash []byte, now time.Time) (string, error) {
	id, err := randomToken(24)
	if err != nil {
		return "", err
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	for key, item := range service.ceremonies {
		if item.expiresAt.Before(now) {
			delete(service.ceremonies, key)
		}
	}
	service.ceremonies[id] = ceremony{kind: kind, session: session, tokenHash: append([]byte(nil), tokenHash...), expiresAt: now.Add(5 * time.Minute)}
	return id, nil
}

func (service *Service) take(id, kind string, now time.Time) (ceremony, error) {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	item, found := service.ceremonies[id]
	delete(service.ceremonies, id)
	if !found || item.kind != kind || item.expiresAt.Before(now) {
		return ceremony{}, ErrCeremonyInvalid
	}
	return item, nil
}

func (service *Service) encryptCredential(credential webauthn.Credential) ([]byte, error) {
	plain, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(service.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte("HAVEN WebAuthn credential v1")), nil
}

func (service *Service) decryptCredential(value []byte) (webauthn.Credential, error) {
	var credential webauthn.Credential
	block, err := aes.NewCipher(service.key)
	if err != nil {
		return credential, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return credential, err
	}
	if len(value) < gcm.NonceSize() {
		return credential, errors.New("stored passkey credential is invalid")
	}
	plain, err := gcm.Open(nil, value[:gcm.NonceSize()], value[gcm.NonceSize():], []byte("HAVEN WebAuthn credential v1"))
	if err != nil {
		return credential, errors.New("stored passkey credential could not be decrypted")
	}
	if err := json.Unmarshal(plain, &credential); err != nil {
		return credential, err
	}
	return credential, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if value, err := os.ReadFile(path); err == nil {
		if len(value) != 32 {
			return nil, errors.New("HAVEN credential encryption key has an invalid length")
		}
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read credential encryption key: %w", err)
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
			return os.ReadFile(path)
		}
		return nil, fmt.Errorf("create credential encryption key: %w", err)
	}
	if _, err := file.Write(value); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return value, nil
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
