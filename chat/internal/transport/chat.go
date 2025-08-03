package transport

import (
	"context"
	"net/http"
	"encoding/json"
	"errors"

	"nhooyr.io/websocket"
	"go.uber.org/zap"
	"github.com/jackc/pgx/v5"

	"chat_service/pkg/logger"
	iaes "chat_service/pkg/aes"
)

func (t Transport) ChatWSHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		OriginPatterns: []string{"none"},
	})
	if err != nil {
		logger.Warn(ctx, "Protocol upgrading error", zap.Error(err))
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	sessionKey, err := t.handleHandshake(ctx, conn)
	if err != nil {
		if errors.Is(err, invalidVersionError) {
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid version")...))
			return
		}
		logger.Warn(ctx, "Handshake error", zap.Error(err))
		return
	}

	peerID := -1

	for {
		_, enc, err := conn.Read(context.Background())
		if err != nil {
			return
		}

		payload, err := iaes.Decrypt(sessionKey, enc)
		if err != nil {
			logger.Warn(ctx, "InstAES decoding error", zap.Error(err))
			continue
		}

		var result []byte

		switch enc[0] {
		case 5:
			if peerID < 0 {
				result = append([]byte{127}, []byte("Unauthorized")...)
				// ret [127, U, n, a, u, ...]
				break
			}

			chats, err := t.pool.GetChatListByID(peerID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = append([]byte{10}, []byte("[]")...)
					// ret [10, '[', ']']
					break
				}
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(chats)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				return
			}
			result = append([]byte{10}, jsonbytes...)
			break
		case 6:
			if peerID < 0 {
				result = append([]byte{127}, []byte("Unauthorized")...)
				// ret [127, U, n, a, u, ...]
				break
			}
			var req SearchRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				return
			}

			users, err := t.pool.SearchUsersByQuery(req.Query)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = append([]byte{11}, []byte("[]")...)
					// ret [11, '[', ']']
					break
				}
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(users)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				return
			}
			result = append([]byte{11}, jsonbytes...)
			break
		case 7:
			if peerID < 0 {
				result = append([]byte{127}, []byte("Unauthorized")...)
				// ret [127, U, n, a, u, ...]
				break
			}
			var req NewChatRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				return
			}

			label1, err := t.pool.GetNameByUserID(req.User2)
			if err != nil {
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}
			
			label2, err := t.pool.GetNameByUserID(peerID)
			if err != nil {
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			chatID, err := t.pool.InsertChat(peerID, req.User2, label1, label2)
			if err != nil {
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(NewChatResponse{chatID})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				return
			}
			result = append([]byte{12}, jsonbytes...)
			break
		case 8:
			if peerID < 0 {
				result = append([]byte{127}, []byte("Unauthorized")...)
				// ret [127, U, n, a, u, ...]
				break
			}
			var req GetMessagesRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				return
			}

			messages, err := t.pool.GetMessageListByUserIDAndChatIDAndParams(peerID, req.ChatID, req.Num, req.Offset)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = append([]byte{13}, []byte("[]")...)
					// ret [13, '[', ']']
					break
				}
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(messages)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				return
			}
			result = append([]byte{13}, jsonbytes...)
			break
		case 9:
			if peerID < 0 {
				result = append([]byte{127}, []byte("Unauthorized")...)
				// ret [127, U, n, a, u, ...]
				break
			}
			var req SendMessageRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				return
			}

			messageID, ts, err := t.pool.InsertMessage(peerID, req.Receiver, req.ChatID, req.Body)
			if err != nil {
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(SendMessageResponse{messageID, ts})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				return
			}
			result = append([]byte{14}, jsonbytes...)

			receiverConn, connected := t.connmap[req.Receiver]
			if !connected {break}
			jsonbytes, err = json.Marshal(GotMessageAck{req.ChatID, messageID, ts, req.Body})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				return
			}
			enc, err := iaes.Encrypt(receiverConn.sessionKey, jsonbytes)
			if err != nil {
				logger.Warn(ctx, "Encryption error", zap.Error(err))
				break
			}
			receiverConn.conn.Write(context.Background(), websocket.MessageBinary, append([]byte{15}, enc...))
			break
		case 16:
			var req RegisterTokenRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				return
			}
			id, login, err := t.parseToken(req.Token)
			if err != nil {
				if errors.Is(err, tokenExpiredError) {
					result = append([]byte{127}, []byte("Unauthorized")...)
					// ret [127, U, n, a, u, ...]
					break
				}
				logger.Warn(ctx, "Token error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal token error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}
			if !t.pool.VerifyLoginAndID(login, id) {
				result = append([]byte{127}, []byte("Invalid credentials")...)
				// ret [127, I, n, v, a, l, ...]
				break
			}
			t.Lock()
			t.connmap[id] = SecureConn{conn, sessionKey}
			t.Unlock()
			logger.Info(ctx, "Connected", zap.Int("id", id))
			peerID = id
			defer func() {
				t.Lock()
				delete(t.connmap, id)
				t.Unlock()
				logger.Info(ctx, "Disconnected", zap.Int("id", id))
			}()
			result = []byte{17}
			// ret [17]
			break
		default:
			logger.Warn(ctx, "Invalid payload: " + string(payload), zap.Int("invalidMessageType", int(enc[0])))
			return
		}

		resp := []byte{}
		if len(result) > 1 {
			resp, err = iaes.Encrypt(sessionKey, result[1:])
			if err != nil {
				logger.Warn(ctx, "Encryption error", zap.Error(err))
				continue
			}
		}

		if err := conn.Write(context.Background(), websocket.MessageBinary, append([]byte{result[0]}, resp...)); err != nil {
			return
		}
	}
}