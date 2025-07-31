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
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"chat_service/pkg/logger"
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