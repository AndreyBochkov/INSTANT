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

	"nhooyr.io/websocket"
	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/bcrypt"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/google/uuid"

	"auth_service/pkg/logger"
	iaes "auth_service/pkg/aes"
	"auth_service/pkg/postgres"
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
	alicePublic = alicePublic[1:]

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

		switch enc[0] {
		case 1:
			var req RegisterRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}
			if req.Login == "" || req.Password == "" {
				result = append([]byte{127}, []byte("Empty credentials")...)
				// ret [127, E, m, p, t, y, ...]
				break
			}

			passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			if err != nil {
				logger.Warn(r.Context(), "Bcrypt error", zap.Error(err))
				result = append([]byte{127}, []byte("Pass encryption error")...)
				// ret [127, P, a, s, s, ...]
				break
			}

			err = t.pool.InsertUser(req.Login, string(passwordHash), req.Name)
			if err != nil {
				if strings.Contains(err.Error(), "23505") {
					result = append([]byte{127}, []byte("Duplicated login")...)
					// ret [127, D, u, p, l, i, ...]
					break
				}
				logger.Warn(r.Context(), "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}
			result = []byte{3}
			// ret [3]
			break
		case 2:
			var req LoginRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(r.Context(), "JSON decoder error", zap.Error(err))
				return
			}

			id, name, passwordHash, err := t.pool.GetIDAndNameAndPasswordByLogin(req.Login)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					result = append([]byte{127}, []byte("Invalid credentials")...) // login
					// ret [127, I, n, v, a, l, ...]
					break
				} else {
					logger.Warn(r.Context(), "Postgres error", zap.Error(err))
					result = append([]byte{127}, []byte("Internal DB error")...)
					// ret [127, I, n, t, e, r, ...]
					break
				}
			}

			if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
				result = append([]byte{127}, []byte("Invalid credentials")...) // password
				// ret [127, I, n, v, a, l, ...]
				break
			}

			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"iss": req.Login,
				"sub": id,
				"exp": time.Now().Add(48*time.Hour).Unix(),
			}).SignedString([]byte(t.jwtKey))
			if err != nil {
				logger.Warn(r.Context(), "JWT error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal token error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			if err := t.pool.EditKeyByUserID(id, sessionKey); err != nil {
				logger.Warn(r.Context(), "Postgres error", zap.Error(err))
				result = append([]byte{127}, []byte("Internal DB error")...)
				// ret [127, I, n, t, e, r, ...]
				break
			}

			jsonbytes, err := json.Marshal(LoginResponse{Name: name, Token: token})
			if err != nil {
				logger.Warn(r.Context(), "JSON encoder error", zap.Error(err))
				return
			}
			result = append([]byte{4}, jsonbytes...)
			break
		default:
			logger.Warn(r.Context(), "Invalid payload: " + string(enc) + string(payload))
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