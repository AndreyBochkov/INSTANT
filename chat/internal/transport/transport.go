package transport

import (
	"context"
	"net/http"
	"encoding/json"
	"crypto/rand"
	"time"
	"crypto/sha256"
	"errors"
	"strconv"

	"nhooyr.io/websocket"
	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/google/uuid"

	"chat_service/pkg/logger"
	iaes "chat_service/pkg/aes"
	"chat_service/pkg/postgres"
)

func New(pool postgres.PGXPool, jwtKey string, version int) Transport {
	return Transport{pool: pool, jwtKey: jwtKey, version: version}
}

func (t Transport) handleHandshake(ctx context.Context, conn *websocket.Conn) ([]byte, error) {
	_, alicePublic, err := conn.Read(context.Background())
    if err != nil {
        return nil, err
    }

	version := int(alicePublic[0])
	alicePublic := alicePublic[1:]

	if len(alicePublic) != 32 {
		return nil, errors.New("Invalid handshake pattern")
	}

	if version != t.version {
		return nil, invalidVersionError
	}

	bobPrivate := make([]byte, 32)
	rand.Read(bobPrivate)
	bobPublic, err := curve25519.X25519(bobPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	sharedPre, err := curve25519.X25519(bobPrivate, alicePublic)
	if err != nil {
		return nil, err
	}

	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)

	sessionKey := make([]byte, 32)
	hkdf.New(sha256.New, sharedPre, serverRandom, nil).Read(sessionKey)

    if err := conn.Write(context.Background(), websocket.MessageBinary, append(append(append([]byte{0}, bobPublic...), serverRandom...), []byte(ctx.Value(logger.RequestIDKey).(string))...)); err != nil {
        return nil, err
    }

	// ret [0, B, K, ..., E, Y, R, A, ..., N, D, R, E, Q, ..., I, D]

    return sessionKey, nil
}

func (t Transport) parseToken(strtoken string) (int, string, error) {
	token, err := jwt.ParseWithClaims(strtoken, &jwt.MapClaims{}, func(token *jwt.Token)(interface{},error){return[]byte(t.jwtKey),nil})
	exp, err := token.Claims.GetExpirationTime()
	if err != nil {return 0, "", err}
	if exp.Before(time.Now()) {return 0, "", tokenExpiredError}
	strsub, err := token.Claims.GetSubject()
	if err != nil {return 0, "", err}
	sub, err := strconv.Atoi(strsub)
	if err != nil {return 0, "", err}
	iss, err := token.Claims.GetIssuer()
	if err != nil {return 0, "", err}

	return sub, iss, nil
}

func (t Transport) disconnect(id int) {
	t.Lock()
	delete(t.connmap, id)
	t.Unlock()
}

func (t Transport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		OriginPatterns: []string{"*"},
	})
    if err != nil {
		logger.Warn(r.Context(), "Protocol upgrading error", zap.Error(err))
		return
	}
    defer conn.Close(websocket.StatusNormalClosure, "")

	sessionKey, err := t.handleHandshake(r.Context(), conn)
    if err != nil {
		if errors.Is(err, invalidVersionError) {
			conn.Write(context.Background(), websocket.MessageBinary, []byte{15})
			return
		}
        logger.Warn(r.Context(), "Handshake error", zap.Error(err))
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
			logger.Warn(r.Context(), "InstAES decoding error", zap.Error(err))
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
			var req GetChatsRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
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
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
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
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
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
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
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
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}

			chatID, err := t.pool.InsertChat(peerID, req.User2, req.Label1, req.Label2)
			if err != nil {
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(NewChatResponse{chatID})
			if err != nil {
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
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
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
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
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
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
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}

			messageID, ts, err := t.pool.InsertMessage(peerID, req.ChatID, req.Body)
			if err != nil {
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(SendMessageResponse{messageID, ts})
			if err != nil {
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
				return
			}
			result = append([]byte{14}, jsonbytes...)

			receiverConn, connected := t.connmap[req.Receiver]
			if connected {
				jsonbytes, err := json.Marshal(GotMessageAck{req.ChatID, messageID, ts, req.Body})
				if err != nil {
					logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
					return
				}
				enc, err := iaes.Encrypt(receiverConn.sessionKey, jsonbytes)
				if err != nil {
					logger.Warn(r.Context(), "Encryption error", zap.Error(err))
					break
				}
				receiverConn.conn.Write(context.Background(), websocket.MessageBinary, append([]byte{18}, enc...))
				break
			}
			receiverSessionKey, err := t.pool.GetSessionKeyBySyncableID(req.Receiver)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					break
				}
				logger.Warn(r.Context(), "Postgres error", zap.Error(err))
				break
			}
			t.pool.InsertSyncRecord(req.Receiver, /* TODO: sync record body */, receiverSessionKey)
			break
		case 16:
			var req RegisterTokenRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}
			id, login, err := t.parseToken(req.Token)
			if err != nil {
				if errors.Is(err, tokenExpiredError) {
					result = append([]byte{127}, []byte("Unauthorized")...)
					// ret [127, U, n, a, u, ...]
					break
				}
				logger.Warn(r.Context(), "Token error", zap.Error(err))
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
			logger.Info(r.Context, "Connected", zap.Int("id", id))
			peerID = id
			defer func() {
				t.disconnect(id)
				logger.Info(r.Context, "Disconnected", zap.Int("id", id))
			}()
			result = []byte{17}
			// ret [17]
			break
		default:
			logger.Warn(r.Context(), "Invalid payload: " + string(payload), zap.Int("invalidMessageType", int(enc[0])))
			return
		}

        resp := []byte{}
		if len(result) > 1 {
			resp, err = iaes.Encrypt(sessionKey, result[1:])
			if err != nil {
				logger.Warn(r.Context(), "Encryption error", zap.Error(err))
				continue
			}
		}

        if err := conn.Write(context.Background(), websocket.MessageBinary, append([]byte{result[0]}, resp...)); err != nil {
            return
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