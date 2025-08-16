package transport

import (
	"context"
	"net/http"
	"encoding/json"
	"strings"
	"errors"
	"strconv"
	"time"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"nhooyr.io/websocket"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"github.com/jackc/pgx/v5"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/hkdf"

	"instant_service/pkg/logger"
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

	sessionKey, err := t.handleHandshake(ctx, conn)
	if err != nil {
		if errors.Is(err, invalidVersionError) {
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid version")...))
			return
		}
		logger.Warn(ctx, "Handshake error", zap.Error(err))
		conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid handshake pattern")...))
		return
	}

	peerID := -1

	for {
		_, enc, err := conn.Read(context.Background())
		if err != nil {
			logger.Info(ctx, "Receive: Error", zap.Error(err))
			return
		}

		payload, err := iaes.Decrypt(sessionKey, enc)
		if err != nil {
			logger.Warn(ctx, "InstAES decoding error", zap.Error(err))
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Internal AES error")...))
			return
		}

		var result []byte

		switch enc[0] {
		case 1:
			var req RegisterRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}
			if req.Login == "" || req.Password == "" {
				result = []byte{126}
				break
			}

			passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			if err != nil {
				logger.Warn(ctx, "Bcrypt error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal bcrypt error")...)
				break
			}

			err = t.pool.InsertUser(req.Login, string(passwordHash), req.Name)
			if err != nil {
				if strings.Contains(err.Error(), "23505") {
					result = []byte{125} // duplicated login
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}
			result = []byte{3}
			break
		case 2:
			var req LoginRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}

			id, name, passwordHash, err := t.pool.GetIDAndNameAndPasswordByLogin(req.Login)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = []byte{124} // invalid login
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}

			if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
				result = []byte{124} // invalid password
				break
			}

			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub":	id,
				"iss":	"instant",
				"exp":	time.Now().Add(48*time.Hour),
			}).SignedString(t.jwtKey)
			if err != nil {
				logger.Warn(ctx, "JWT error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal error")...)
				break
			}

			jsonbytes, err := json.Marshal(LoginResponse{Name: name, Token: token})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
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
			result = append([]byte{4}, jsonbytes...)
			break
		case 5:
			if peerID < 0 {
				logger.Info(ctx, "Requesting while unauthorized")
				result = append([]byte{127}, []byte("Unauthorized")...)
				break
			}

			chats, err := t.pool.GetChatListByID(peerID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = append([]byte{10}, []byte("[]")...)
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
			result = append([]byte{10}, jsonbytes...)
			break
		case 6:
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
					result = append([]byte{11}, []byte("[]")...)
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
			result = append([]byte{11}, jsonbytes...)
			break
		case 7:
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

			label1, err := t.pool.GetNameByUserID(req.User2)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				break
			}
			
			label2, err := t.pool.GetNameByUserID(peerID)
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

			jsonbytes, err := json.Marshal(NewChatResponse{chatID})
			if err != nil {
				logger.Warn(ctx, "JSON encoder error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal JSON error")...)
				break
			}
			result = append([]byte{12}, jsonbytes...)
			break
		case 8:
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

			messages, err := t.pool.GetMessageListByUserIDAndChatIDAndParams(peerID, req.ChatID, req.Num, req.Offset)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = append([]byte{13}, []byte("[]")...)
					break
				}
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
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
				logger.Info(ctx, "Requesting while unauthorized")
				result = append([]byte{127}, []byte("Unauthorized")...)
				break
			}
			var req SendMessageRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				return
			}

			messageID, ts, err := t.pool.InsertMessage(peerID, req.Receiver, req.ChatID, req.Body)
			if err != nil {
				logger.Warn(ctx, "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
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
					logger.Info(ctx, "Send: Error", zap.Error(err))
					return
				}
			}
		}
	}
}

func (t Transport) SyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Bad method", http.StatusBadRequest)
		return
	}

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusBadRequest)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return t.jwtKey, nil
	})
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusBadRequest)
		return
	}
	if !token.Valid {
		http.Error(w, "Unauthorized", http.StatusBadRequest)
		return
	}

	iss, err := token.Claims.GetIssuer()
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusBadRequest)
		return
	}
	if iss != "instant" {
		http.Error(w, "Unauthorized", http.StatusBadRequest)
		return
	}

	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusBadRequest)
		return
	}
	if exp.Before(time.Now()) {
		http.Error(w, "Expired", http.StatusBadRequest)
		return
	}

	sub, err := token.Claims.GetSubject()
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(sub)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusBadRequest)
		return
	}

	var req SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn(r.Context(), "Error in JSON decoder", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	bobPublic, sharedPre, err := t.parsePayload(req.Handshake)
	if err != nil {
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