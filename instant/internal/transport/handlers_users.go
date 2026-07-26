package transport

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"instant_service/pkg/logger"
	"instant_service/internal/security"
)

func (t Transport) handleRegister(ctx context.Context, sc security.SecureConn, req RegisterRequest, respType int) error {
	if req.Login == "" {
		sc.RawSend(security.Payload{Type: 126, Data: ""})
		break
	}

	restricted := false
	for _, r := range req.Login {
		if !((r >= 'a' && r <= 'z') || 
			(r >= 'A' && r <= 'Z') || 
			(r >= '0' && r <= '9') || 
			(r == '_')) {
			restricted = true
			break
		}
	}
	if restricted {
		logger.Info(ctx, fmt.Sprintf("Register: Restricted login: %s", req.Login))
		sc.RawSend(security.Payload{Type: 123, Data: ""})
		break
	}

	if t.pool.CheckLogin(req.Login) {
		logger.Info(ctx, "Register: Duplicated login")
		sc.RawSend(security.Payload{Type: 125, Data: ""})
		break
	}

	id, err := t.pool.InsertUser(sc.IKey(), req.Login, req.Img)
	if err != nil {
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}

	sc.SetPeerID(id)

	t.routineWelcome(ctx, sc)
	defer t.routineGoodbye(ctx, sc)

	jsonbytes, err := t.routineGetJsonBytes(ctx, sc, p.User{UserID: id, Login: req.Login, Img: req.Img})
	if err != nil { return err }
	sc.SecureSend(security.Payload{Type: respType, Data: string(jsonbytes)})
	return nil
}

func (t Transport) handleSearch(ctx content.Context, sc security.SecureConn, req SearchRequest, respType int) error {
	users, err := t.pool.SearchUsersByQuery(strings.ReplaceAll(strings.ReplaceAll(req.Query, "%", "\\%"), "_", "\\_")+"%")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sc.SecureSend(security.Payload{Type: 53, Data: "[]"})
			break
		}
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}

	jsonbytes, err := t.routineGetJsonBytes(ctx, sc, users)
	if err != nil { return err }
	sc.SecureSend(security.Payload{Type: respType, Data: string(jsonbytes)})
	return nil
}

func (t Transport) handleGetAdmins(ctx context.Context, sc security.SecureConn, req GetAdminsRequest, respType int) error {
	// получить список админов может кто угодно из этого чата. даже в очереди на принятие <=> {}
	if err := t.routineRequireRoles(ctx, sc, req.ChatID, []string{}); err != nil { return err }

	admins, err = t.pool.GetAdminsByChatID(req.ChatID)
	if err != nil {
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}

	jsonbytes, err := t.routineGetJsonBytes(ctx, sc, GetAdminsResponse{ChatID: req.ChatID, Admins: admins})
	if err != nil { return err }
	sc.SecureSend(security.Payload{Type: respType, Data: string(jsonbytes)})
	return nil
}

func (t Transport) handleGetListeners(ctx context.Context, sc security.SecureConn, req GetListenersRequest, respType int) error {
	// получить список слушателей можно только админам
	if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

	listeners, err = t.pool.GetListenersByChatID(req.ChatID)
	if err != nil {
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}

	jsonbytes, err := t.routineGetJsonBytes(ctx, sc, GetListenersResponse{ChatID: req.ChatID, Listeners: listeners})
	if err != nil { return err }
	sc.SecureSend(security.Payload{Type: respType, Data: string(jsonbytes)})
	return nil
}

func (t Transport) handleGetQueued(ctx context.Context, sc security.SecureConn, req GetQueuedRequest, respType int) error {
	// получить список очереди можно только админам
	if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

	queued, err = t.pool.GetQueuedByChatID(req.ChatID)
	if err != nil {
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}

	jsonbytes, err := t.routineGetJsonBytes(ctx, sc, GetQueuedResponse{ChatID: req.ChatID, Queued: queued})
	if err != nil { return err }
	sc.SecureSend(security.Payload{Type: respType, Data: string(jsonbytes)})
	return nil
}