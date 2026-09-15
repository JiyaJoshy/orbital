//go:build integration

package handler_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/armada/orbital/internal/auth"
	"github.com/armada/orbital/internal/handler"
	"github.com/labstack/echo/v4"
)

var loginTestKeys = auth.SessionKeys{HMACKey: "test-login-hmac-key"}

func newLoginHandler() *handler.Login {
	return handler.NewLogin(testDB, loginTestKeys, "", slog.Default())
}

// sessionWithCSRF creates a fresh CSRF token in a session cookie and returns
// the cookie jar (for the next request) and the token value.
func sessionWithCSRF(t *testing.T) ([]*http.Cookie, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	token, err := auth.GetOrCreateCSRF(loginTestKeys, req, rec)
	if err != nil {
		t.Fatalf("GetOrCreateCSRF: %v", err)
	}
	return rec.Result().Cookies(), token
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestLogout_ValidCSRF(t *testing.T) {
	h := newLoginHandler()
	cookies, csrf := sessionWithCSRF(t)

	e := echo.New()
	body := strings.NewReader(url.Values{"csrf": {csrf}}.Encode())
	req := httptest.NewRequest(http.MethodPost, "/user/logout", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Logout(c); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if rec.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", rec.Code)
	}
}

func TestLogout_InvalidCSRF(t *testing.T) {
	h := newLoginHandler()
	cookies, _ := sessionWithCSRF(t)

	e := echo.New()
	body := strings.NewReader(url.Values{"csrf": {"bad-csrf"}}.Encode())
	req := httptest.NewRequest(http.MethodPost, "/user/logout", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Logout(c); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	// Invalid CSRF still redirects (graceful degradation)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", rec.Code)
	}
}
