package transport

import (
	"context"
	"net/http"
	"crypto/rand"
	"crypto/sha256"
	"crypto/ed25519"

	"nhooyr.io/websocket"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"github.com/google/uuid"

	"instant_service/pkg/logger"
	"instant_service/pkg/postgres"
)

func New(pool postgres.PGXPool, jwtKey string, version int) Transport {
	return Transport{pool: pool, jwtKey: jwtKey, version: version}
}

func (t Transport) parsePayload(payload []byte) ([]byte, []byte, error) {
	if len(payload) != 97 {
		return []byte{}, []byte{}, handshakeFault
	}

	version := int(payload[0])
	if version != t.version {
		return []byte{}, []byte{}, invalidVersionError
	}

	alicePublic := payload[1:33]
	aliseSigned := payload[33:65]
	aliceSignature := payload[65:]
	if !ed25519.Verify(alicePublic, aliseSigned, aliceSignature) {
		return []byte{}, []byte{}, verificationError
	}

	bobPrivate := make([]byte, 32)
	rand.Read(bobPrivate)
	bobPublic, err := curve25519.X25519(bobPrivate, curve25519.Basepoint)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	sharedPre, err := curve25519.X25519(bobPrivate, aliseSigned)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return bobPublic, sharedPre, nil
}

func (t Transport) handleHandshake(ctx context.Context, conn *websocket.Conn) ([]byte, error) {
	_, payload, err := conn.Read(context.Background())
	if err != nil {
		return nil, err
	}

	bobPublic, sharedPre, err := t.parsePayload(payload)
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