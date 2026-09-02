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
	ErrNotConfigured   = errors.New("passkey authentication has not been configured")
	ErrCeremonyInvalid = errors.New("authentication ceremony is invalid or expired")
	ErrSessionInvalid  = errors.New("authentication session is invalid or expired")
	ErrCSRFInvalid     = errors.New("anti-forgery token is invalid")
	ErrReauthorization = errors.New("fresh passkey confirmation is required")
	ErrFinalPasskey    = errors.New("the final passkey cannot be removed")
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
	grants     map[string]authorizationGrant
}

type ceremony struct {
	kind      string
	session   webauthn.SessionData
	tokenHash []byte
	label     string
	scope     string
	expiresAt time.Time
}

type authorizationGrant struct {
	sessionHash [32]byte
	scope       string
	expiresAt   time.Time
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

type PasskeyInfo struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
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
	return &Service{store: store, webAuthn: instance, key: key, origin: origin, secureCookies: parsed.Scheme == "https", ceremonies: map[string]ceremony{}, attempts: map[string]attemptWindow{}, grants: map[string]authorizationGrant{}}, nil
}

func (service *Service) Origin() string      { return service.origin }
func (service *Service) SecureCookies() bool { return service.secureCookies }

func CreateBootstrap(ctx context.Context, store *storage.Store, validFor time.Duration, now time.Time) (string, error) {
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

func (service *Service) BeginRegistration(ctx context.Context, bootstrapCode, label string, now time.Time) (CeremonyResponse, error) {
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
	return service.beginRegistration(user, "bootstrap-registration", tokenHash[:], label, now)
}

func (service *Service) BeginAdditionalRegistration(ctx context.Context, label string, now time.Time) (CeremonyResponse, error) {
	user, err := service.loadUser(ctx)
	if err != nil {
		return CeremonyResponse{}, err
	}
	return service.beginRegistration(user, "additional-registration", nil, label, now)
}

func (service *Service) beginRegistration(user *User, kind string, tokenHash []byte, label string, now time.Time) (CeremonyResponse, error) {
	label = normalizeLabel(label)
	exclusions := make([]protocol.CredentialDescriptor, 0, len(user.credentials))
	for _, credential := range user.credentials {
		exclusions = append(exclusions, credential.Descriptor())
	}
	creation, session, err := service.webAuthn.BeginRegistration(user, webauthn.WithExclusions(exclusions))
	if err != nil {
		return CeremonyResponse{}, err
	}
	ceremonyID, err := service.remember(kind, *session, tokenHash, label, "", now)
	if err != nil {
		return CeremonyResponse{}, err
	}
	return CeremonyResponse{CeremonyID: ceremonyID, PublicKey: creation.Response}, nil
}

func (service *Service) FinishRegistration(ctx context.Context, ceremonyID string, request *http.Request, now time.Time) (Session, error) {
	stored, err := service.take(ceremonyID, "bootstrap-registration", now)
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
	if err := service.store.CompleteAuthBootstrap(ctx, stored.tokenHash, credential.ID, encrypted, stored.label, now); err != nil {
		return Session{}, err
	}
	_ = service.store.AppendAudit(ctx, storage.AuditEvent{Actor: "owner", Action: "auth.passkey.register", Target: "owner", Outcome: "succeeded", Detail: "A new HAVEN passkey was registered.", OccurredAt: now})
	return service.NewSession(ctx, now)
}

func (service *Service) FinishAdditionalRegistration(ctx context.Context, ceremonyID string, request *http.Request, now time.Time) (PasskeyInfo, error) {
	stored, err := service.take(ceremonyID, "additional-registration", now)
	if err != nil {
		return PasskeyInfo{}, err
	}
	user, err := service.loadUser(ctx)
	if err != nil {
		return PasskeyInfo{}, err
	}
	credential, err := service.webAuthn.FinishRegistration(user, stored.session, request)
	if err != nil {
		return PasskeyInfo{}, err
	}
	encrypted, err := service.encryptCredential(*credential)
	if err != nil {
		return PasskeyInfo{}, err
	}
	if err := service.store.AddAuthCredential(ctx, credential.ID, encrypted, stored.label, now); err != nil {
		return PasskeyInfo{}, err
	}
	_ = service.store.AppendAudit(ctx, storage.AuditEvent{Actor: "owner", Action: "auth.passkey.add", Target: "owner", Outcome: "succeeded", Detail: "An additional owner passkey was registered.", OccurredAt: now})
	return PasskeyInfo{ID: base64.RawURLEncoding.EncodeToString(credential.ID), Label: stored.label, CreatedAt: now}, nil
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
	ceremonyID, err := service.remember("login", *session, nil, "", "", now)
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
	if _, err := service.finishPasskeyAssertion(ctx, stored, request, now); err != nil {
		return Session{}, err
	}
	_ = service.store.AppendAudit(ctx, storage.AuditEvent{Actor: "owner", Action: "auth.login", Target: "owner", Outcome: "succeeded", Detail: "Passkey sign-in succeeded.", OccurredAt: now})
	return service.NewSession(ctx, now)
}

func (service *Service) finishPasskeyAssertion(ctx context.Context, stored ceremony, request *http.Request, now time.Time) (*webauthn.Credential, error) {
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
		return nil, err
	}
	if matched == nil {
		return nil, errors.New("passkey owner could not be resolved")
	}
	encrypted, err := service.encryptCredential(*credential)
	if err != nil {
		return nil, err
	}
	if err := service.store.UpdateAuthCredential(ctx, credential.ID, encrypted, now); err != nil {
		return nil, err
	}
	return credential, nil
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
	expires := now.Add(30 * 24 * time.Hour)
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

func (service *Service) Passkeys(ctx context.Context) ([]PasskeyInfo, error) {
	records, err := service.store.AuthCredentials(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]PasskeyInfo, 0, len(records))
	for _, record := range records {
		result = append(result, PasskeyInfo{ID: base64.RawURLEncoding.EncodeToString(record.ID), Label: record.Label, CreatedAt: record.CreatedAt, LastUsedAt: record.LastUsedAt})
	}
	return result, nil
}

func (service *Service) RemovePasskey(ctx context.Context, encodedID string, now time.Time) error {
	id, err := base64.RawURLEncoding.DecodeString(encodedID)
	if err != nil || len(id) == 0 {
		return errors.New("invalid passkey identity")
	}
	if err := service.store.DeleteAuthCredential(ctx, id); err != nil {
		if errors.Is(err, storage.ErrFinalAuthCredential) {
			return ErrFinalPasskey
		}
		return err
	}
	_ = service.store.AppendAudit(ctx, storage.AuditEvent{Actor: "owner", Action: "auth.passkey.remove", Target: "owner", Outcome: "succeeded", Detail: "An owner passkey was removed.", OccurredAt: now})
	return nil
}

func (service *Service) BeginReauthorization(ctx context.Context, scope string, now time.Time) (CeremonyResponse, error) {
	if scope == "" || len(scope) > 180 {
		return CeremonyResponse{}, ErrReauthorization
	}
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
	ceremonyID, err := service.remember("reauthorization", *session, nil, "", scope, now)
	if err != nil {
		return CeremonyResponse{}, err
	}
	return CeremonyResponse{CeremonyID: ceremonyID, PublicKey: assertion.Response}, nil
}

func (service *Service) FinishReauthorization(ctx context.Context, ceremonyID, sessionToken string, request *http.Request, now time.Time) (string, error) {
	valid, err := service.ValidateSession(ctx, sessionToken, now)
	if err != nil || !valid {
		return "", ErrSessionInvalid
	}
	stored, err := service.take(ceremonyID, "reauthorization", now)
	if err != nil {
		return "", err
	}
	if _, err := service.finishPasskeyAssertion(ctx, stored, request, now); err != nil {
		return "", err
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	tokenHash := sha256.Sum256([]byte(token))
	sessionHash := sha256.Sum256([]byte(sessionToken))
	service.mutex.Lock()
	for key, grant := range service.grants {
		if grant.expiresAt.Before(now) {
			delete(service.grants, key)
		}
	}
	service.grants[base64.RawURLEncoding.EncodeToString(tokenHash[:])] = authorizationGrant{sessionHash: sessionHash, scope: stored.scope, expiresAt: now.Add(2 * time.Minute)}
	service.mutex.Unlock()
	_ = service.store.AppendAudit(ctx, storage.AuditEvent{Actor: "owner", Action: "auth.reauthorize", Target: stored.scope, Outcome: "succeeded", Detail: "A fresh passkey confirmation authorized one sensitive operation.", OccurredAt: now})
	return token, nil
}

func (service *Service) ConsumeReauthorization(sessionToken, token, scope string, now time.Time) error {
	if sessionToken == "" || token == "" {
		return ErrReauthorization
	}
	tokenHash := sha256.Sum256([]byte(token))
	key := base64.RawURLEncoding.EncodeToString(tokenHash[:])
	sessionHash := sha256.Sum256([]byte(sessionToken))
	service.mutex.Lock()
	defer service.mutex.Unlock()
	grant, found := service.grants[key]
	delete(service.grants, key)
	if !found || grant.expiresAt.Before(now) || grant.scope != scope || subtle.ConstantTimeCompare(grant.sessionHash[:], sessionHash[:]) != 1 {
		return ErrReauthorization
	}
	return nil
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

func (service *Service) remember(kind string, session webauthn.SessionData, tokenHash []byte, label, scope string, now time.Time) (string, error) {
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
	service.ceremonies[id] = ceremony{kind: kind, session: session, tokenHash: append([]byte(nil), tokenHash...), label: label, scope: scope, expiresAt: now.Add(5 * time.Minute)}
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

func normalizeLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Passkey"
	}
	if len(value) > 60 {
		return value[:60]
	}
	return value
}
