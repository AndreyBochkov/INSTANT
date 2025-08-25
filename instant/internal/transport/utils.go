package transport

import (
	"context"
	"net/http"
	"crypto/rand"
	"crypto/sha256"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"nhooyr.io/websocket"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"github.com/google/uuid"

	"instant_service/pkg/logger"
	"instant_service/pkg/postgres"
)

func New(pool postgres.PGXPool, version int, rotationInterval int) Transport {
	return Transport{pool: pool, version: version, rotationInterval: rotationInterval, connmap: map[int]SecureConn{}}
}

func (t Transport) parsePayload(payload []byte) (int, []byte, []byte, []byte, error) {
	if len(payload) <= 98 {
		return -1, nil, nil, nil, handshakeFault
	}

	if int(payload[0]) != t.version {
		return -1, nil, nil, nil, invalidVersionError
	}

	alicePublicXY := payload[1:65] // compressed [X][Y]
	aliceSigned := payload[65:97]
	aliceSignature := payload[97:] // asn.1 block

	alicePublic := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X: new(big.Int).SetBytes(alicePublicXY[:32]),
		Y: new(big.Int).SetBytes(alicePublicXY[32:64]),
	}

	hash := sha256.New()
	hash.Write(aliceSigned)
	if !ecdsa.VerifyASN1(alicePublic, hash.Sum(nil), aliceSignature) {
		return -1, nil, nil, nil, verificationError
	}

	id := t.pool.GetIDByIKeyUpdatingTS(alicePublicXY)

	bobPrivate := make([]byte, 32)
	rand.Read(bobPrivate)
	bobPublic, err := curve25519.X25519(bobPrivate, curve25519.Basepoint)
	if err != nil {
		return -1, nil, nil, nil, err
	}

	sharedPre, err := curve25519.X25519(bobPrivate, aliceSigned)
	if err != nil {
		return -1, nil, nil, nil, err
	}

	return id, alicePublicXY, bobPublic, sharedPre, nil
}

func (t Transport) handleHandshake(ctx context.Context, conn *websocket.Conn) (int, []byte, []byte, error) {
	_, payload, err := conn.Read(context.Background())
	if err != nil {
		return -1, nil, nil, err
	}

	id, iKey, bobPublic, sharedPre, err := t.parsePayload(payload)
	if err != nil {
		return -1, nil, nil, err
	}

	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)

	sessionKey := make([]byte, 32)
	hkdf.New(sha256.New, sharedPre, serverRandom, nil).Read(sessionKey)

	msgType := 0
	if id != -1 {
		msgType = 1
	}

	if err := conn.Write(context.Background(), websocket.MessageBinary, append(append(append([]byte{byte(msgType)}, bobPublic...), serverRandom...), []byte(ctx.Value(logger.RequestIDKey).(string))...)); err != nil {
		return -1, nil, nil, err
	}

	return id, iKey, sessionKey, nil
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