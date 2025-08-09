package transport

import (
	"context"
	"net/http"
	"crypto/rand"
	"time"
	"crypto/sha256"
	"errors"
	"strconv"

	"nhooyr.io/websocket"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"github.com/google/uuid"

	"chat_service/pkg/logger"
	"chat_service/pkg/postgres"
)

func New(pool postgres.PGXPool, jwtKey string, version int) Transport {
	return Transport{pool: pool, jwtKey: jwtKey, version: version}
}

func (t Transport) handleHandshake(ctx context.Context, conn *websocket.Conn) ([]byte, error) {
	_, payload, err := conn.Read(context.Background())
	if err != nil {
		return nil, err
	}

	version := int(payload[0])
	alicePublic := payload[1:]

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