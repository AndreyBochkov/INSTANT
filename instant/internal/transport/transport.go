package transport

import (
	"context"
	"net/http"
	"encoding/json"
	"errors"
	"time"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"github.com/jackc/pgx/v5"
	"github.com/google/uuid"

	"instant_service/pkg/logger"
	p "instant_service/pkg/postgres"
	"instant_service/internal/security"
)

func New(pool p.PGXPool) Transport {
	return Transport{pool: pool, connmap: map[int](*security.SecureConn){}}
}

func (t Transport) MainHandler(ctx context.Context, sc *security.SecureConn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if sc.PeerID() != -1 {
		t.routineWelcome(ctx, sc)
		defer t.routineGoodbye(ctx, sc)
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			err := sc.Ping(ctx)
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// TODO: [развести все эп по разным функциям и ]добавить большой общий канал с новостями

	for {
		payload, err := sc.SecureRecv(ctx)
		if err != nil {
			return errors.New(fmt.Sprintf("Receive: Error: %w", err))
		}

		switch payload.Type {
		case 11: // Register
			if sc.PeerID() != -1 {
				logger.Warn(ctx, "Register while authorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Authorized"})
				return AuthorizedError
			}
			var req RegisterRequest
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}
			if err = t.handleRegister(ctx, sc, req, 51); err != nil { return err }
			break

		case 13: // Search
			var req SearchRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }
			if err = t.handleRegister(ctx, sc, req, 53); err != nil { return err }
			break
		
		case 14: // GetAdmins
			var req GetAdminsRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }
			if err = t.handleGetAdmins(ctx, sc, req, 54); err != nil { return err }
			break

		case 15: // GetListeners
			var req GetListenersRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }
			if err = t.handleGetListeners(ctx, sc, req, 55); err != nil { return err }
			break

		case 16: // GetQueued
			var req GetQueuedRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }
			if err = t.handleGetQueued(ctx, sc, req, 56); err != nil { return err }
			break

		case 21: // GetAllEvents
			var req GetAllEventsRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }
			if err = t.handleGetAllEvents(ctx, sc, req, 61); err != nil { return err }
			break

		case 22: // GetChatEvents
			var req GetChatEventsRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }
			if err = t.handleGetChatEvents(ctx, sc, req, 62); err != nil { return err }
			break
		
		case 23: // Event
			var req EventRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }
			if err = t.handleEvent(ctx, sc, req, 63); err != nil { return err }
			break

		case 31: // ReadMessage
			var req ReadMessageRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }

			// прочитать сообщение можно только если ты админ или слушатель чата в котором соо
			if err := t.routineRequireRoles(ctx, sc, req.ChatID, []string{"admin", "listener"}); err != nil { return err }

			err := UpdateReadStatusByTODO()
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			sc.SecureSend(security.Payload{Type: 71, Data: payload.Data})
			break

		case 32: // WhoReadThis TODO
			var req WhoReadThisRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }

			// получить список очереди можно только админам
			if err := t.routineRequireRole(ctx, sc, req.ChatID, "admin"); err != nil { return err }

			read, err = t.pool.GetWhoReadByEventID()
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			jsonbytes, err := t.routineGetJsonBytes(ctx, sc, listeners)
			if err != nil { return err }
			sc.SecureSend(security.Payload{Type: 53, Data: string(jsonbytes)})
			break

		case 41: // WhoIsThis TODO
			// без разбору всем и каждому можно

		case 42: // UseLink TODO
			// без разбору, записаться в очередь можно всем

		case 48: // WhoAmI
			jsonbytes, err := t.routineGetJsonBytes(ctx, sc, WhoAmI{Login: t.pool.GetLoginByID(sc.PeerID()), Id: sc.PeerID()})
			if err != nil { return err }
			sc.SecureSend(security.Payload{Type: 88, Data: string(jsonbytes)})
			break
		case 50: // ChangeIKey
			var req ChangeIKeyRequest
			if err = t.routineDecodePayload(ctx, sc, &req, payload); err != nil { return err }

			err = t.pool.UpdateIKeyByID(sc.PeerID(), req.New)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			sc.SecureSend(security.Payload{Type: 90, Data: ""})
			break
		default:
			return errors.New(fmt.Sprintf("Invalid message type %d during reading payload %x", payload.Type, []byte(payload.Data)))
		}
	}
}

func MiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		guid := uuid.New().String()
		ctx, err := logger.New(r.Context())
		if err == nil {
			ctx = context.WithValue(ctx, logger.RequestIDKey, guid)
			logger.Info(ctx, "Initiating connection")
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		}
	})
}