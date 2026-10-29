// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
)

// TestWhoami_TransientErrorIsNot401 is a regression test for the error
// classification fix in #4581. A transient infrastructure error (e.g.
// context.Canceled from a pool-wait that got cancelled, driver timeout)
// returned by FetchFromRequest must not be reported to the client as 401 —
// 401 misleads clients into treating a still-valid session as logged out.
func TestWhoami_TransientErrorIsNot401(t *testing.T) {
	_, reg := pkg.NewFastRegistryWithMocks(t)

	// Create an identity + active session so a valid token exists in the DB.
	i := identity.Identity{Traits: []byte("{}"), State: identity.StateActive}
	require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(context.Background(), &i))

	seed := httptest.NewRequest(http.MethodGet, "/", nil)
	s, err := testhelpers.NewActiveSession(seed, reg, &i, time.Now(), identity.CredentialsTypePassword, identity.AuthenticatorAssuranceLevel1)
	require.NoError(t, err)
	require.NoError(t, reg.SessionPersister().UpsertSession(context.Background(), s))

	// Build a whoami request with the valid token, then attach a context
	// that is already cancelled. The DB lookup inside FetchFromRequest runs
	// against this cancelled context, so pop returns context.Canceled rather
	// than sql.ErrNoRows — the exact class of error that was previously
	// flattened into 401 by the handler.
	req := httptest.NewRequest(http.MethodGet, RouteWhoami, nil)
	req.Header.Set("X-Session-Token", s.Token)
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	// whoami is unexported — this test lives in package session so it can
	// invoke the handler directly, bypassing routing and middleware.
	reg.SessionHandler().whoami(w, req)

	assert.NotEqualf(t, http.StatusUnauthorized, w.Code,
		"transient lookup errors must not be reported as 401; got body=%s", w.Body.String())
}
