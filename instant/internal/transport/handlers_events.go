package transport

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"instant_service/pkg/logger"
	"instant_service/internal/security"
)

func (t Transport) handleGetAllEvents(ctx context.Context, sc security.SecureConn, req GetAllEventsRequest, respType int) error {
	// пользователю можно запрашивать список всех ивентов во всех доступных чатах после указанного ts. Если среди них есть add_tie для нашего пользователя, то он тут же запрашивает данные, до которых может дотянуться (22)
	events, err := t.pool.GetEventsByUserIDAndAfter(sc.PeerID(), req.FromID)
	// TODO: что делать с событиями, до которых пользователь не может дотянуться из-за роли? Как их отсеивать?
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}

	jsonbytes, err := t.routineGetJsonBytes(ctx, sc, events)
	if err != nil { return err }
	sc.SecureSend(security.Payload{Type: respType, Data: string(jsonbytes)})
	return nil
}

func (t Transport) handleGetChatEvents(ctx context.Context, sc security.SecureConn, req GetChatEventsRequest, respType int) error {
	if role, err = t.pool.GetRoleByUserIDAndChatID(sc.PeerID(), req.ChatID); err != nil {
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}
	// пользователь точно есть в чате, ему можно запрашивать список событий конкретного чата до момента добавления
	events, err := t.pool.GetEventsByUserIDAndChatIDAndRoleAndBefore(sc.PeerID(), req.ChatID, role, req.ToID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		logger.Warn(ctx, "Postgres error", zap.Error(err))
		sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
		return InternalDBError
	}

	jsonbytes, err := t.routineGetJsonBytes(ctx, sc, events)
	if err != nil { return err }
	sc.SecureSend(security.Payload{Type: respType, Data: string(jsonbytes)})
	return nil
}

func (t Transport) handleEvent(ctx context.Context, sc security.SecureConn, req EventRequest, respType int) error {
	var event p.Event

	switch req.Eventtype {
	case "add_chat":
		var chatData ChatData
		if err = t.routineDecodePayload(ctx, sc, &chatData, req.Content); err != nil { return err }

		eventid, chatid, ts, err := t.pool.AddChatWithAdminByChatDataAndUserID(chatData.Label, chatData.Img, sc.PeerID())
		if err != nil {
			logger.Warn(ctx, "Postgres error", zap.Error(err))
			sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
			return InternalDBError
		}
		event = p.Event{
			EventID: eventid,
			Ts: ts,
			Eventtype: req.Eventtype,
			ChatID: chatid,
			UserID: sc.PeerID,
			SubID: 0,
			Content: req.Content,
		}
		break

	case "upd_chat":
		if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

		var chatData ChatData
		if err = t.routineDecodePayload(ctx, sc, &chatData, req.Content); err != nil { return err }

		eventid, ts, err := t.pool.UpdChatDataByChatIDAndNew(req.ChatID, chatData.Label, chatData.Img)
		if err != nil {
			logger.Warn(ctx, "Postgres error", zap.Error(err))
			sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
			return InternalDBError
		}
		event = p.Event{
			EventID: eventid,
			Ts: ts,
			Eventtype: req.Eventtype,
			ChatID: chatid,
			UserID: sc.PeerID(),
			SubID: 0,
			Content: req.Content,
		}
		break

	case "del_chat":
		if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

		eventid, ts, err := t.pool.MarkChatAsDeleted(req.ChatID)
		if err != nil {
			logger.Warn(ctx, "Postgres error", zap.Error(err))
			sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
			return InternalDBError
		}
		event = p.Event{
			EventID: eventid,
			Ts: ts,
			Eventtype: req.Eventtype,
			ChatID: chatid,
			UserID: 0,
			SubID: 0,
			Content: []byte{},
		}
		break

	case "add_message":
		if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

		eventid, ts, err := t.pool.AddMessageByUserIDAndChatIDAndContent(sc.PeerID(), req.ChatID, req.Content)
		if err != nil {
			logger.Warn(ctx, "Postgres error", zap.Error(err))
			sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
			return InternalDBError
		}
		event = p.Event{
			EventID: eventid,
			Ts: ts,
			Eventtype: req.Eventtype,
			ChatID: chatid,
			UserID: sc.PeerID(),
			SubID: 0,
			Content: req.Content,
		}
		break

	case "add_react":
		if err := t.routineRequireRoles(ctx, sc, req.ChatID, []string{"admin", "listener"}); err != nil { return err }

		break

	case "del_message"
		if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

		break

	case "add_tie":
		if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

		break

	case "upd_tie":
		if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

		break

	case "del_tie":
		if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

		break
	
	case "add_link":
		if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

		break
	
	case "del_link":
		if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

		break
	}

	jsonbytes, err := t.routineGetJsonBytes(ctx, sc, event)
	if err != nil { return err }
	sc.SecureSend(security.Payload{Type: respType, Data: string(jsonbytes)})
}