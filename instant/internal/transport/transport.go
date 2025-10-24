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

	"instant_service/pkg/logger"
	"instant_service/pkg/postgres"
	"instant_service/internal/security"
)

func New(pool postgres.PGXPool) Transport {
	return Transport{pool: pool, connmap: map[int](*SecureConn){}}
}

func (t Transport) MainHandler(ctx context.Context, sc *security.SecureConn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if sc.PeerID() != -1 {
		t.Lock()
		t.connmap[sc.PeerID()] = sc
		t.Unlock()
		logger.Info(ctx, "Welcome!", zap.Int("userId", sc.PeerID()))
		defer func() {
			t.Lock()
			delete(t.connmap, sc.PeerID())
			t.Unlock()
			logger.Info(ctx, "Goodbye!", zap.Int("userId", sc.PeerID()))
		}()
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

	for {
		payload, err := sc.SecureRecv(ctx)
		if err != nil {
			return errors.New(fmt.Sprintf("Receive: Error: %w", err))
		}

		var result security.Payload

		switch payload.Type {
		case 11: // Register
			if sc.PeerID() != -1 {
				logger.Warn(ctx, "Register while authorized")
				result = security.Payload{Type: 127, Data: "Authorized"}
				break
			}
			var req RegisterRequest
			if err := json.Unmarshal(payload.Data, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}
			if req.Login == "" {
				result = security.Payload{Type: 126, Data: ""}
				break
			}

			if t.pool.CheckLogin(req.Login) {
				logger.Info(ctx, "Register: Duplicated login")
				result = security.Payload{Type: 125, Data: ""}
				break
			}

			id, err := t.pool.InsertUser(sc.IKey(), req.Login)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			t.Lock()
			t.connmap[id] = sc
			t.Unlock()
			logger.Info(ctx, "Welcome!", zap.Int("userId", id))
			defer func() {
				t.Lock()
				delete(t.connmap, id)
				t.Unlock()
				logger.Info(ctx, "Goodbye!", zap.Int("userId", id))
			}()
			sc.PeerID(id)
			result = security.Payload{Type: 51, Data: "")
			break
		case 12: //GetChats
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = security.Payload{Type: 127, Data: "Unauthorized"}
				break
			}

			chats, err := t.pool.GetChatListByID(sc.PeerID())
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = security.Payload{Type: 52, Data: "[]"}
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			jsonbytes, err := json.Marshal(chats)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}
			result = security.Payload{Type: 52, Data: string(jsonbytes)}
			break
		case 13: //Search
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = security.Payload{Type: 127, Data: "Unauthorized"}
				break
			}
			var req SearchRequest
			if err := json.Unmarshal(payload.Data, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}

			users, err := t.pool.SearchUsersByQuery(strings.ReplaceAll(strings.ReplaceAll(req.Query, "%", "\\%"), "_", "\\_")+"%")
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = security.Payload{Type: 53, Data: "[]"}
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			jsonbytes, err := json.Marshal(users)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}
			result = security.Payload{Type: 53, Data: string(jsonbytes)}
			break
		case 14: //GetProperties
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = security.Payload{Type: 127, Data: "Unauthorized"}
				break
			}
			var req GetPropertiesRequest
			if err := json.Unmarshal(payload.Data, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}

			isAdmin, err = t.pool.GetIsAdminByUserIDAndChatID(sc.PeerID(), req.ChatID) // Проверяем права доступа
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = security.Payload{Type: 124, Data: ""} // TODO: add this error
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			var (
				admins []postgres.User
				listeners []postgres.User
			)
			if isAdmin {
				listeners, err := t.pool.GetListenersByChatID(req.ChatID)
				if err != nil {
					logger.Warn(ctx, "Postgres error", zap.Error(err))
					result = security.Payload{Type: 127, Data: "Internal DB error"}
					break
				}
			} else {
				listeners = []postgres.User{}
			}
			admins, err := t.pool.GetAdminsByChatID(req.ChatID)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			jsonbytes, err := json.Marshal(GetPropertiesResponse{ChatID: req.ChatID, Admins: admins, Listeners: listeners})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}
			result = security.Payload{Type: 54, Data: string(jsonbytes)}
			break
		case 15: //NewChat
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = security.Payload{Type: 127, Data: "Unauthorized"}
				break
			}
			var req NewChatRequest
			if err := json.Unmarshal(payload.Data, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}

			req.Listeners = excludeIntersection(req.Admins, req.Listeners) // Исключим админов из слушателей на всякий случай

			chatID, err := t.pool.InsertChat(append(req.Admins, sc.PeerID()), req.Listeners, req.Label)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			jsonbytes, err := json.Marshal(postgres.Chat{chatID, req.Label})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}
			result = security.Payload{Type: 55, Data: string(jsonbytes)}

			for _, user2 := range req.Users {
				receiverConn, connected := t.connmap[req.User2]
				if !connected {continue}
				receiverConn.SecureSend(result)
			}
			break
		case 16: //GetMessages
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = security.Payload{Type: 127, Data: "Unauthorized"}
				break
			}
			var req GetMessagesRequest
			if err := json.Unmarshal(payload.Data, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}

			isAdmin, err = t.pool.GetIsAdminByUserIDAndChatID(sc.PeerID(), req.ChatID) // Проверяем права доступа
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = security.Payload{Type: 124, Data: ""} // TODO: add this error
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			messages, err := t.pool.GetMessageListByUserIDAndChatIDAndParam(sc.PeerID(), req.ChatID, req.Offset)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = security.Payload{Type: 54, Data: fmt.Sprintf(`{"chatid":%d;"messages":[]}`, req.ChatID)}
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			jsonbytes, err := json.Marshal(GetMessagesResponse{ChatID:req.ChatID, Messages:messages})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}
			result = security.Payload{Type: 54, Data: string(jsonbytes)}
			break
		case 15: //SendMessage
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = security.Payload{Type: 127, Data: "Unauthorized"}
				break
			}
			var req SendMessageRequest
			if err := json.Unmarshal(payload.Data, &req); err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}

			messageID, ts, err := t.pool.InsertMessage(sc.PeerID(), req.ChatID, req.Body)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			jsonbytes, err := json.Marshal(postgres.SyncMessage{messageID, ts, req.Body, req.ChatID})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal JSON error"}
				break
			}
			result = security.Payload{Type: 127, Data: "Unauthorized"}

			receiverConn, connected := t.connmap[req.Receiver]
			if !connected {break}
			jsonbytes, err = json.Marshal(postgres.SyncMessage{messageID, ts, req.Body, req.ChatID})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error (receiverConn)", zap.Error(err))
				break
			}
			receiverConn.SecureSend(security.Payload{Type: 91, Data: string(jsonbytes)})
			break
		case 16:
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = security.Payload{Type: 127, Data: "Unauthorized"}
				break
			}
			var req ChangeIKeyRequest
			if err := json.Unmarshal(payload.Data, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				break
			}

			err = t.pool.UpdateIKeyByID(sc.PeerID(), req.New)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = security.Payload{Type: 127, Data: "Internal DB error"}
				break
			}

			result = security.Payload{Type: 56, Data: ""}
			break
		default:
			return errors.New(fmt.Sprintf("Invalid message type %d during reading payload %x", enc[0], string(payload.Data)))
		}

		if result.Type > 100 { // Ошибка
			conn.RawSend(result)
			if result.Type == 127 { // Фатальная ошибка
				return errors.New(result.Data)
			}
		} else  { // Не ошибка
			conn.SecureSend(result)
		}
	}
}

func MiddlewareHandler(next func (w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		guid := uuid.New().String()
		ctx, err := logger.New(r.Context())
		if err == nil {
			ctx = context.WithValue(ctx, logger.RequestIDKey, guid)
			logger.Info(ctx, "Initiating connection")
			r = r.WithContext(ctx)
			next(w, r)
		}
	})
}