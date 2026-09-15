package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/armada/orbital/ent"
	"github.com/armada/orbital/internal/auth"
	"github.com/labstack/echo/v4"
)

// Login handles session teardown for orbital's Keycloak-only browser login
// (see internal/handler/orgsvc_oidc.go for sign-in). No local email/password
// path — Logout works the same regardless of how the session was
// established.
type Login struct {
	db          *ent.Client
	sessionKeys auth.SessionKeys
	basePath    string
	logger      *slog.Logger
}

func NewLogin(db *ent.Client, sessionKeys auth.SessionKeys, basePath string, logger *slog.Logger) *Login {
	return &Login{db: db, sessionKeys: sessionKeys, basePath: basePath, logger: logger}
}

// Logout handles POST /user/logout.
func (h *Login) Logout(c echo.Context) error {
	csrf := c.FormValue("csrf")
	// Read actor before clearing the session.
	actor, _ := c.Get("user_email").(string)
	ua := c.Request().UserAgent()
	if !auth.ValidateCSRF(h.sessionKeys, c.Request(), csrf) {
		return c.Redirect(http.StatusSeeOther, h.basePath+"/")
	}
	if err := auth.ClearSession(h.sessionKeys, c.Request(), c.Response()); err != nil {
		return fmt.Errorf("clear session: %w", err)
	}
	h.writeAuthAudit("logout", actor, map[string]any{"user_agent": ua})
	return c.Redirect(http.StatusSeeOther, h.basePath+"/")
}

// writeAuthAudit persists an authentication audit event. No-op if db is nil.
func (h *Login) writeAuthAudit(operation, actor string, details map[string]any) {
	if h.db == nil {
		return
	}
	writeAuditEvent(h.db, h.logger, "auth", actor, operation,
		[]string{operation},
		[]string{},
		[]string{},
		details,
	)
}
