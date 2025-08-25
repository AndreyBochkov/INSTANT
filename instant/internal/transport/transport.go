package transport

import (
	"context"
	"net/http"
	"encoding/json"
	"strings"
	"errors"
	"time"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"nhooyr.io/websocket"
	"go.uber.org/zap"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/hkdf"

	"instant_service/pkg/logger"
	"instant_service/pkg/postgres"
	iaes "instant_service/pkg/aes"
)

func (t Transport) MainHandler(w http.ResponseWriter, r *http.Request) {
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

	peerID, iKey, sessionKey, err := t.handleHandshake(ctx, conn)
	if err != nil {
		if errors.Is(err, invalidVersionError) {
			logger.Info(ctx, "Old version request")
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid version")...))
			return
		}
		logger.Warn(ctx, "Handshake error", zap.Error(err))
		conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid handshake pattern")...))
		return
	}

	if peerID != -1 {
		t.Lock()
		t.connmap[peerID] = SecureConn{conn, sessionKey}
		t.Unlock()
		logger.Info(ctx, "Welcome!", zap.Int("userId", peerID))
		defer func() {
			t.Lock()
			delete(t.connmap, peerID)
			t.Unlock()
			logger.Info(ctx, "Goodbye!", zap.Int("userId", peerID))
		}()
	}

	rotationTs := time.Now().Unix()

	for {
		_, enc, err := conn.Read(context.Background())
		if err != nil {
			logger.Info(ctx, "Receive: Error", zap.Error(err))
			return
		}

		payload, err := iaes.Decrypt(sessionKey, enc)
		if err != nil && err != iaes.ZeroLengthCiphertextError {
			logger.Warn(ctx, "InstAES decoding error", zap.Error(err))
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Internal AES error")...))
			return
		}

		var result []byte

		switch enc[0] {
		case 17: // Register
			if peerID != -1 {
				logger.Warn(ctx, "Register while authorized")
				result = append([]byte{127}, []byte("Authorized")...)
				break
			}
			var req RegisterRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}
			if req.Login == "" {
				result = []byte{126}
				break
			}

			id, err := t.pool.InsertUser(iKey, req.Login)
			if err != nil {
				if strings.Contains(err.Error(), "23505") {
					logger.Info(ctx, "Register: Duplicated login")
					result = []byte{125}
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}

			t.Lock()
			t.connmap[id] = SecureConn{conn, sessionKey}
			t.Unlock()
			logger.Info(ctx, "Welcome!", zap.Int("userId", id))
			defer func() {
				t.Lock()
				delete(t.connmap, id)
				t.Unlock()
				logger.Info(ctx, "Goodbye!", zap.Int("userId", id))
			}()
			peerID = id
			result = []byte{57}
			break
		case 11: //GetChats
			if peerID < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = append([]byte{127}, []byte("Unauthorized")...)
				break
			}

			chats, err := t.pool.GetChatListByID(peerID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = append([]byte{51}, []byte("[]")...)
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}

			jsonbytes, err := json.Marshal(chats)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}
			result = append([]byte{51}, jsonbytes...)
			break
		case 12: //Search
			if peerID < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = append([]byte{127}, []byte("Unauthorized")...)
				break
			}
			var req SearchRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}

			users, err := t.pool.SearchUsersByQuery(req.Query)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = append([]byte{52}, []byte("[]")...)
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}

			jsonbytes, err := json.Marshal(users)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}
			result = append([]byte{52}, jsonbytes...)
			break
		case 13: //NewChat
			if peerID < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = append([]byte{127}, []byte("Unauthorized")...)
				break
			}
			var req NewChatRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}

			label1, err := t.pool.GetLoginByUserID(req.User2)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}
			
			label2, err := t.pool.GetLoginByUserID(peerID)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}

			chatID, err := t.pool.InsertChat(peerID, req.User2, label1, label2)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}

			jsonbytes, err := json.Marshal(postgres.Chat{chatID, req.User2, label1})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}
			result = append([]byte{53}, jsonbytes...)

			receiverConn, connected := t.connmap[req.User2]
			if !connected {break}
			jsonbytes, err = json.Marshal(postgres.Chat{chatID, peerID, label2})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				break
			}
			enc, err := iaes.Encrypt(receiverConn.sessionKey, jsonbytes)
			if err != nil {
				logger.Warn(ctx, "Encryption error", zap.Error(err))
				break
			}
			receiverConn.conn.Write(context.Background(), websocket.MessageBinary, append([]byte{53}, enc...))
			break
		case 14: //GetMessages
			if peerID < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = append([]byte{127}, []byte("Unauthorized")...)
				break
			}
			var req GetMessagesRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}

			messages, err := t.pool.GetMessageListByUserIDAndChatIDAndParam(peerID, req.ChatID, req.Offset)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = append([]byte{54}, []byte("[]")...)
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}

			jsonbytes, err := json.Marshal(messages)
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}
			result = append([]byte{54}, jsonbytes...)
			break
		case 15: //SendMessage
			if peerID < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = append([]byte{127}, []byte("Unauthorized")...)
				break
			}
			var req SendMessageRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}

			messageID, ts, err := t.pool.InsertMessage(peerID, req.Receiver, req.ChatID, req.Body)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}

			jsonbytes, err := json.Marshal(postgres.SyncMessage{messageID, ts, req.Body, req.ChatID})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}
			result = append([]byte{55}, jsonbytes...)

			receiverConn, connected := t.connmap[req.Receiver]
			if !connected {break}
			jsonbytes, err = json.Marshal(postgres.SyncMessage{messageID, ts, req.Body, req.ChatID})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				break
			}
			enc, err := iaes.Encrypt(receiverConn.sessionKey, jsonbytes)
			if err != nil {
				logger.Warn(ctx, "Encryption error", zap.Error(err))
				break
			}
			receiverConn.conn.Write(context.Background(), websocket.MessageBinary, append([]byte{15}, enc...))
			break
		case 16:
			if peerID < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = append([]byte{127}, []byte("Unauthorized")...)
				break
			}
			var req ChangeIKeyRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				break
			}

			err = t.pool.UpdateIKeyByID(peerID, req.New)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}

			result = []byte{56}
			break
		default:
			logger.Warn(ctx, "Invalid message type. Payload: " + string(payload), zap.Int("invalidMessageType", int(enc[0])))
			return
		}

		if len(result) > 1 {
			if result[0] > 100 {
				conn.Write(context.Background(), websocket.MessageBinary, result)
				if result[0] == 127 {
					return
				}
			} else {
				resp, err := iaes.Encrypt(sessionKey, result[1:])
				if err != nil {
					logger.Warn(ctx, "Encryption error", zap.Error(err))
					conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Internal AES error")...))
					return
				}
				if err := conn.Write(context.Background(), websocket.MessageBinary, append([]byte{result[0]}, resp...)); err != nil {
					logger.Warn(ctx, "Send: Error", zap.Error(err))
					return
				}
			}
		} else {
			if err := conn.Write(context.Background(), websocket.MessageBinary, result); err != nil {
				logger.Warn(ctx, "Send: Error", zap.Error(err))
				return
			}
		}

		if peerID != -1 {
			now := time.Now().Unix()
			if int(now-rotationTs) > t.rotationInterval {
				serverRandom := make([]byte, 32)
				rand.Read(serverRandom)

				if err := conn.Write(context.Background(), websocket.MessageBinary, append([]byte{92}, serverRandom...)); err != nil {
					logger.Warn(ctx, "RotateKeys: Send: Error", zap.Error(err))
					return
				}

				hkdf.New(sha256.New, serverRandom, sessionKey, nil).Read(sessionKey)
				rotationTs = now
			}
		}
	}
}

func (t Transport) SyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Bad method", http.StatusBadRequest)
		return
	}

	var req SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn(r.Context(), "Error in JSON decoder", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	id, _, bobPublic, sharedPre, err := t.parsePayload(req.Handshake)
	if err != nil || id == -1{
		logger.Warn(r.Context(), "Handshake error", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	messages, err := t.pool.GetSyncMessageListByReceiverIDAndAfter(id, req.After)
	if err != nil {
		logger.Warn(r.Context(), "Postgres error", zap.Error(err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)

	sessionKey := make([]byte, 32)
	hkdf.New(sha256.New, sharedPre, serverRandom, nil).Read(sessionKey)

	jsonbytes, err := json.Marshal(messages)
	if err != nil {
		logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	enc, err := iaes.Encrypt(sessionKey, jsonbytes)
	if err != nil {
		logger.Warn(r.Context(), "INSTAES error", zap.Error(err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(append(append(bobPublic, serverRandom...), enc...)))
}