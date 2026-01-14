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
	"instant_service/pkg/postgres"
	"instant_service/internal/security"
)

func New(pool postgres.PGXPool) Transport {
	return Transport{pool: pool, connmap: map[int](*security.SecureConn){}}
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

			if req.Login == "" {
				sc.RawSend(security.Payload{Type: 126, Data: ""})
				break
			}

			if t.pool.CheckLogin(req.Login) {
				logger.Info(ctx, "Register: Duplicated login")
				sc.RawSend(security.Payload{Type: 125, Data: ""})
				break
			}

			id, err := t.pool.InsertUser(sc.IKey(), req.Login)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
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

			sc.SetPeerID(id)

			jsonbytes, err := json.Marshal(WhoAmI{Login: t.pool.GetLoginByID(id), Id: id})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			sc.SecureSend(security.Payload{Type: 51, Data: string(jsonbytes)})
			break
		case 12: //GetChats
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}

			chats, err := t.pool.GetChatListByID(sc.PeerID())
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					sc.SecureSend(security.Payload{Type: 52, Data: "[]"})
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			jsonbytes, err := json.Marshal(chats)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}
			sc.SecureSend(security.Payload{Type: 52, Data: string(jsonbytes)})
			break
		case 13: //Search
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}
			var req SearchRequest
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

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

			jsonbytes, err := json.Marshal(users)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}
			sc.SecureSend(security.Payload{Type: 53, Data: string(jsonbytes)})
			break
		case 14: //GetProperties
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}
			var req GetPropertiesRequest
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			isAdmin, err := t.pool.GetIsAdminByUserIDAndChatID(sc.PeerID(), req.ChatID) // Проверяем права доступа
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			var (
				admins []postgres.User
				listeners []postgres.User
			)
			if isAdmin {
				listeners, err = t.pool.GetListenersByChatID(req.ChatID)
				if err != nil {
					logger.Warn(ctx, "Postgres error", zap.Error(err))
					sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
					return InternalDBError
				}
			} else {
				listeners = []postgres.User{}
			}
			admins, err = t.pool.GetAdminsByChatID(req.ChatID)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			jsonbytes, err := json.Marshal(GetPropertiesResponse{ChatID: req.ChatID, Admins: admins, Listeners: listeners})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}
			sc.SecureSend(security.Payload{Type: 54, Data: string(jsonbytes)})
			break
		case 15: //NewChat
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}
			var req NewChatRequest
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			req.Listeners = excludeIntersection(req.Admins, req.Listeners) // Исключим админов из слушателей на всякий случай

			// TODO: проверять идентификаторы пользователей на реальность и исключать повторяющиеся (как?)

			chatID, err := t.pool.InsertChat(append(req.Admins, sc.PeerID()), req.Listeners, req.Label)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			adminjsonbytes, err := json.Marshal(postgres.Chat{chatID, req.Label, true})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			adminAck := security.Payload{Type: 55, Data: string(adminjsonbytes)}
			sc.SecureSend(adminAck)

			for _, user2 := range req.Admins {
				receiverConn, connected := t.connmap[user2]
				if !connected {continue}
				receiverConn.SecureSend(adminAck)
			}

			listenerjsonbytes, err := json.Marshal(postgres.Chat{chatID, req.Label, false})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			listenerAck := security.Payload{Type: 55, Data: string(listenerjsonbytes)}

			for _, user2 := range req.Listeners {
				receiverConn, connected := t.connmap[user2]
				if !connected {continue}
				receiverConn.SecureSend(listenerAck)
			}
			break

		// TODO: больше не допустить НАСТОЛЬКО огромной дыры в безопасности

		// Написав свой клиент для рукопожатия, кто-либо мог послать запрос
		// GetMessages с любым chatid и сервер ему ответил бы!

		case 16: //GetMessages
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}
			var req GetMessagesRequest
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			_, err = t.pool.GetIsAdminByUserIDAndChatID(sc.PeerID(), req.ChatID) // Проверяем права доступа
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			messages, err := t.pool.GetMessageListByChatIDAndParam(req.ChatID, req.Offset)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					sc.SecureSend(security.Payload{Type: 56, Data: fmt.Sprintf(`{"chatid":%d;"messages":[]}`, req.ChatID)})
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			jsonbytes, err := json.Marshal(GetMessagesResponse{ChatID:req.ChatID, Messages:messages})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}
			sc.SecureSend(security.Payload{Type: 56, Data: string(jsonbytes)})
			break
		case 17: //SendMessage
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}
			var req SendMessageRequest
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			isAdmin, err := t.pool.GetIsAdminByUserIDAndChatID(sc.PeerID(), req.ChatID) // Проверяем права доступа
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}
			if !isAdmin {
				sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
				break
			}

			messageID, ts, err := t.pool.InsertMessage(sc.PeerID(), req.ChatID, req.Body)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			jsonbytes, err := json.Marshal(SyncMessage{req.ChatID, messageID, ts, req.Body, sc.PeerID()})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			for _, user := range t.pool.GetUsersByChatID(req.ChatID) {
				receiverConn, connected := t.connmap[user]
				if !connected {continue}
				receiverConn.SecureSend(security.Payload{Type: 57, Data: string(jsonbytes)})
			}
			break
		case 18: // AddTie
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}
			var req postgres.Tie
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}
			
			_, err := t.pool.GetIsAdminByUserIDAndChatID(req.UserID, req.ChatID)
			if !errors.Is(err, pgx.ErrNoRows) {
				sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
				break
			}

			isAdmin, err := t.pool.GetIsAdminByUserIDAndChatID(sc.PeerID(), req.ChatID) // Проверяем права доступа
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}
			if !isAdmin {
				sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
				break
			}

			err = t.pool.InsertTieByIDAndChatIDAndRole(req.UserID, req.ChatID, req.CanSend)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			jsonbytes, err := json.Marshal(AddTieResponse{UserID: req.UserID, ChatID: req.ChatID, Login: t.pool.GetLoginByID(req.UserID), CanSend: req.CanSend})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			for _, user := range t.pool.GetUsersByChatID(req.ChatID) {
				if user == req.UserID {continue}
				receiverConn, connected := t.connmap[user]
				if !connected {continue}
				receiverConn.SecureSend(security.Payload{Type: 58, Data: string(jsonbytes)})
			}

			newUserConn, connected := t.connmap[req.UserID]
			if connected {
				newUserBytes, err := json.Marshal(postgres.Chat{ChatID: req.ChatID, Label: t.pool.GetLabelByChatID(req.ChatID), CanSend: req.CanSend})
				if err != nil {
					logger.Warn(ctx, "JSON encoder error", zap.Error(err))
					break
				}

				newUserConn.SecureSend(security.Payload{Type: 55, Data: string(newUserBytes)})
			}
			break
		case 19: // DeleteTie
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}
			var req DeleteTieData
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			deletedIsAdmin, err := t.pool.GetIsAdminByUserIDAndChatID(req.UserID, req.ChatID)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			isAdmin, err := t.pool.GetIsAdminByUserIDAndChatID(sc.PeerID(), req.ChatID) // Проверяем права доступа
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}
			if !isAdmin {
				sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
				break
			}

			err = t.pool.DeleteTieByIDAndChatID(req.UserID, req.ChatID)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			if !deletedIsAdmin { // Слушатели не увидят удаления другого слушателя
				for _, user := range t.pool.GetAdminsIDsByChatID(req.ChatID) {
					if user == req.UserID {continue}
					receiverConn, connected := t.connmap[user]
					if !connected {continue}
					receiverConn.SecureSend(security.Payload{Type: 59, Data: payload.Data})
				}
				break
			}
			
			for _, user := range t.pool.GetUsersByChatID(req.ChatID) {
				if user == req.UserID {continue}
				receiverConn, connected := t.connmap[user]
				if !connected {continue}
				receiverConn.SecureSend(security.Payload{Type: 59, Data: payload.Data})
			}

			// С точки зрения удаляемого в любом случае пропадает чат

			deletedBytes, err := json.Marshal(postgres.Chat{ChatID: req.ChatID, Label: t.pool.GetLabelByChatID(req.ChatID), CanSend: true})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				break
			}
			deletedConn, connected := t.connmap[req.UserID]
			if !connected {break}
			deletedConn.SecureSend(security.Payload{Type: 60, Data: string(deletedBytes)})
			break
		case 20: // DeleteChat
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}
			var req DeleteChatData
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}

			isAdmin, err := t.pool.GetIsAdminByUserIDAndChatID(sc.PeerID(), req.ChatID) // Проверяем права доступа
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}
			if !isAdmin {
				sc.RawSend(security.Payload{Type: 127, Data: "Access denied!"})
				break
			}

			err = t.pool.MarkChatAsDeletedByChatID(req.ChatID)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}
			
			for _, user := range t.pool.GetUsersByChatID(req.ChatID) {
				receiverConn, connected := t.connmap[user]
				if !connected {continue}
				receiverConn.SecureSend(security.Payload{Type: 60, Data: payload.Data})
			}
			break
		case 48: // WhoAmI
			jsonbytes, err := json.Marshal(WhoAmI{Login: t.pool.GetLoginByID(sc.PeerID()), Id: sc.PeerID()})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}
			sc.SecureSend(security.Payload{Type: 88, Data: string(jsonbytes)})
			break
		
		// TODO: как добавлять оповещения? Пока что через консоль...

		case 49: // GetAlerts
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}

			alerts, err := t.pool.GetAlertsByID(sc.PeerID())
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					sc.SecureSend(security.Payload{Type: 89, Data: "[]"})
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal DB error"})
				return InternalDBError
			}

			jsonbytes, err := json.Marshal(alerts)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				sc.RawSend(security.Payload{Type: 127, Data: "Internal JSON error"})
				return InternalJSONError
			}
			sc.SecureSend(security.Payload{Type: 89, Data: string(jsonbytes)})
			break
		case 50: // ChangeIKey
			if sc.PeerID() < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				sc.RawSend(security.Payload{Type: 127, Data: "Unauthorized"})
				return UnauthorizedError
			}
			var req ChangeIKeyRequest
			if err := json.Unmarshal([]byte(payload.Data), &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				break
			}

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