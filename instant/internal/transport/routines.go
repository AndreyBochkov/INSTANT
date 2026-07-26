package transport

import (
	"context"
	"net/http"
	"encoding/json"
	"errors"
	"time"
	"fmt"
	"strings"
	"slices"

	"go.uber.org/zap"
	"github.com/jackc/pgx/v5"
	"github.com/google/uuid"

	"instant_service/pkg/logger"
	p "instant_service/pkg/postgres"
	"instant_service/internal/security"
)

func (t Transport) routineWelcome(ctx context.Context, sc *security.SecureConn) {
	t.Lock()
	t.connmap[sc.PeerID()] = sc
	t.Unlock()
	logger.Info(ctx, "Welcome!", zap.Int("userId", sc.PeerID()))
}

func (t Transport) routineGoodbye(ctx context.Context, sc *security.SecureConn)  {
	t.Lock()
	delete(t.connmap, sc.PeerID())
	t.Unlock()
	logger.Info(ctx, "Goodbye!", zap.Int("userId", sc.PeerID()))
}

func (t Transport) routineGetJsonBytes(ctx context.Context, sc *security.SecureConn, marshalled any) ([]byte, error) {
	jsonbytes, err := json.Marshal(marshalled)
	if err != nil {
		logger.Warn(ctx, "JSON encoder error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
		return nil, InternalJSONError
	}
	return jsonbytes, nil
}

func (t Transport) routineDecodePayload(ctx context.Context, sc *security.SecureConn, req any, payload security.Payload) error {
	if sc.PeerID() < 0 {
		logger.Info(ctx, "Requesting while unauthorized")
		sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
		return UnauthorizedError
	}
	if err := json.Unmarshal([]byte(payload.Data), req); err != nil {
		logger.Warn(ctx, "JSON encoder error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
		return InternalJSONError
	}
	return nil
}

func (t Transport) routineRequireRole(ctx context.Context, sc *security.SecureConn, chatID int, required string) error {
	role, err := t.pool.GetRoleByUserIDAndChatID(sc.PeerID(), chatID)
	if err != nil {
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}
	if role != required {
		logger.Warn(ctx, "Unauthorized access attempted")
		sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
		return UnauthorizedError
	}
	return nil
}

func (t Transport) routineRequireRoles(ctx context.Context, sc *security.SecureConn, chatID int, required []string) error {
	role, err := t.pool.GetRoleByUserIDAndChatID(sc.PeerID(), chatID)
	if err != nil {
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}
	if !slices.Contains(required, role) {
		logger.Warn(ctx, "Unauthorized access attempted")
		sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
		return UnauthorizedError
	}
	return nil
}