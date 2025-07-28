package transport

import (
	"context"
	"net/http"
	"encoding/json"
	"crypto/rand"
	"time"
	"crypto/sha256"
	"strings"
	"errors"
	"strconv"

	"nhooyr.io/websocket"
	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/bcrypt"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/google/uuid"

	"chat_service/pkg/logger"
	iaes "chat_service/pkg/aes"
	"chat_service/pkg/postgres"
)

func New(pool postgres.PGXPool, jwtKey string) Transport {
	return Transport{pool: pool, jwtKey: jwtKey}
}

func handleHandshake(conn *websocket.Conn) (*[]byte, error) {
	_, alicePublic, err := conn.Read(context.Background())
    if err != nil {
        return nil, err
    }

	if len(alicePublic) != 32 {
		return nil, errors.New("Invalid handshake pattern")
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

func parseToken(strtoken string) (int, string, error) {
	token, err := jwt.ParseWithClaims(strtoken, &jwt.MapClaims{}, func(token *jwt.Token)(interface{},error){return[]byte(t.jwtKey),nil})
	exp, err := token.Claims.GetExpirationTime()
	if err != nil {return "", "", err}
	if exp.Before(time.Now()) {return "", "", tokenExpiredError}
	strsub, err := token.Claims.GetSubject()
	if err != nil {return "", "", err}
	sub, err := strconv.Atoi(strsub)
	if err != nil {return "", "", err}
	iss, err := token.Claims.GetIssuer()
	if err != nil {return "", "", err}

	return sub, iss, nil
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

	sessionKey, err := handleHandshake(conn)
    if err != nil {
        logger.Warn(r.Context(), "Handshake error", zap.Error(err))
        return
    }

	for {
		_, enc, err := conn.Read(context.Background())
        if err != nil {
			logger.Info(r.Context(), "Receive: Error", zap.Error(err))
            return
        }

		payload, err := iaes.Decrypt(sessionKey, enc)
		if err != nil {
			logger.Warn(r.Context(), "InstAES decoding error", zap.Error(err))
			continue
		}

		var result []byte

		var parseIDFromToken = func(token string) (int, bool) {
			id, login, err := parseToken(token)
			if err != nil {
				if errors.Is(err, tokenExpiredError) {
					result = append([]byte{127}, []byte("Unauthorized")...)
					// ret [127, U, n, a, u, ...]
					return 0, false
				}
				logger.Warn(r.Context(), "Token error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal token error")...)
				// ret [127, I, n, t, e, r, ...]
				return 0, false
			}
			if !postgres.VerifyLoginAndID(login, id) {
				result = append([]byte{127}, []byte("Invalid credentials")...)
				// ret [127, I, n, v, a, l, ...]
				return 0, false
			}
			return id, true
		}

		switch enc[0] {
		case 5:
			var req GetChatsRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}
			id, ok := parseIDFromToken(req.Token)
			if !ok {break}

			chats, err := postgres.GetChatListByID(id)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result := append([]byte{10}, []byte("[]")...)
					// ret [10, '[', ']']
					break
				}
				result := append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(chats)
			if err != nil {
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
				return
			}
			result := append([]byte{10}, jsonbytes...)
			break
		case 6:
			var req SearchRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}
			_, ok := parseIDFromToken(req.Token)
			if !ok {break}

			users, err := postgres.SearchUsersByQuery(req.Query)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result := append([]byte{11}, []byte("[]")...)
					// ret [11, '[', ']']
					break
				}
				result := append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(users)
			if err != nil {
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
				return
			}
			result := append([]byte{11}, jsonbytes...)
			break
		case 7:
			var req NewChatRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}
			id, ok := parseIDFromToken(req.Token)
			if !ok {break}

			chatID, err := postgres.InsertChat(id, req.User2)
			if err != nil {
				result := append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(NewChatResponse{chatID})
			if err != nil {
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
				return
			}
			result := append([]byte{12}, jsonbytes...)
			break
		case 8:
			var req GetMessagesRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}
			id, ok := parseIDFromToken(req.Token)
			if !ok {break}

			messages, err := postgres.GetMessageListByUserIDAndChatIDAndParams(id, req.ChatID, req.Num, req.Offset)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result := append([]byte{13}, []byte("[]")...)
					// ret [13, '[', ']']
					break
				}
				result := append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(messages)
			if err != nil {
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
				return
			}
			result := append([]byte{13}, jsonbytes...)
			break
		case 9:
			var req SendMessageRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}
			id, ok := parseIDFromToken(req.Token)
			if !ok {break}

			if err != nil {
				result := append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal()
			if err != nil {
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
				return
			}
			result := append([]byte{14}, jsonbytes...)
			break
		default:
			logger.Warn(r.Context(), "Invalid payload: " + string(payload), zap.Int("invalidMessageType", int(enc[0])))
			return
		}

        resp, err := iaes.Encrypt(sessionKey, result[1:])
        if err != nil {
            logger.Warn(r.Context(), "Encryption error", zap.Error(err))
            continue
        }

		resp = append(result[0], resp...)

        if err := conn.Write(context.Background(), websocket.MessageBinary, resp); err != nil {
            logger.Info(r.Context(), "Send: Error", zap.Error(err))
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