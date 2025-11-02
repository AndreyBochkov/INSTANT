package security

import (
	"context"
	"net/http"
	"crypto/rand"
	"crypto/sha256"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"errors"
	"time"
	"sync"

	"nhooyr.io/websocket"
	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	iaes "instant_service/pkg/aes"
	"instant_service/pkg/logger"
)

func (sc *SecureConn) SecureSend(raw Payload) error {
	if len(raw.Data) == 0 {
		return (*sc).conn.Write(context.Background(), websocket.MessageBinary, []byte{raw.Type})
	}
	enc, err := iaes.Encrypt((*sc).sessionKey, []byte(raw.Data))
	if err != nil {
		(*sc).conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Internal AES error")...))
		return err
	}
	return (*sc).conn.Write(context.Background(), websocket.MessageBinary, append([]byte{raw.Type}, enc...))
}

func (sc *SecureConn) RawSend(raw Payload) error {
	return (*sc).conn.Write(context.Background(), websocket.MessageBinary, append([]byte{raw.Type}, raw.Data...))
}

func (sc *SecureConn) SecureRecv(ctx context.Context) (Payload, error) {
	_, enc, err := (*sc).conn.Read(ctx)
	if err != nil {
		return nilPayload, err
	}

	rawTyped, err := iaes.Decrypt((*sc).sessionKey, enc)
	if err != nil && !errors.Is(err, iaes.ZeroLengthCiphertextError) {
		(*sc).conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Internal AES error")...))
		return nilPayload, err
	}
	return Payload{Type: rawTyped[0], Data: string(rawTyped[1:])}, nil
}

func (sc *SecureConn) Ping(ctx context.Context) error {
	return (*sc).conn.Ping(ctx)
}

func (sc *SecureConn) PeerID() int {
	return (*sc).peerID
}

func (sc *SecureConn) SetPeerID(new int) {
	(*sc).peerID = new
}

func (sc *SecureConn) IKey() []byte {
	return (*sc).iKey
}

func SecurityWSHandler(rotationInterval int, version int, getIDByIKey func (iKey []byte) int, next func (ctx context.Context, sc *SecureConn) error) http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
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

		_, payload, err := conn.Read(ctx)
		if err != nil {
			logger.Warn(ctx, "Receive error", zap.Error(err))
			return
		}

		if len(payload) <= 98 {
			logger.Warn(ctx, "Handshake error", zap.Error(err))
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid handshake pattern")...))
			return
		}
	
		if int(payload[0]) != version {
			logger.Warn(ctx, "Old version request", zap.Error(err))
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid version")...))
			return
		}
	
		alicePublicXY := payload[1:65] // compressed [X][Y]
		aliceSigned := payload[65:97]
		aliceSignature := payload[97:] // asn.1 block
	
		alicePublic := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X: new(big.Int).SetBytes(alicePublicXY[:32]), // [X]
			Y: new(big.Int).SetBytes(alicePublicXY[32:]), // [Y]
		}
	
		hash := sha256.New()
		hash.Write(aliceSigned)
		if !ecdsa.VerifyASN1(alicePublic, hash.Sum(nil), aliceSignature) {
			logger.Warn(ctx, "Verification error", zap.Error(err))
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid handshake pattern")...))
			return
		}
	
		id := getIDByIKey(alicePublicXY)
	
		bobPrivate := make([]byte, 32)
		rand.Read(bobPrivate)
		bobPublic, err := curve25519.X25519(bobPrivate, curve25519.Basepoint)
		if err != nil {
			logger.Warn(ctx, "Handshake error", zap.Error(err))
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid handshake pattern")...))
			return
		}
	
		sharedPre, err := curve25519.X25519(bobPrivate, aliceSigned)
		if err != nil {
			logger.Warn(ctx, "Handshake error", zap.Error(err))
			conn.Write(context.Background(), websocket.MessageBinary, append([]byte{127}, []byte("Invalid handshake pattern")...))
			return
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
			logger.Warn(ctx, "Handshake error", zap.Error(err))
			return
		}

		sc := &SecureConn{conn: conn, sessionKey: sessionKey, peerID: id, iKey: alicePublicXY}

		go func () {
			ticker := time.NewTicker(time.Duration(rotationInterval) * time.Second)
			defer ticker.Stop()
			var mux sync.Mutex

			for range ticker.C {
				serverRandom := make([]byte, 32)
				rand.Read(serverRandom)

				mux.Lock()
				hkdf.New(sha256.New, serverRandom, (*sc).sessionKey, nil).Read((*sc).sessionKey)
				if err := conn.Write(context.Background(), websocket.MessageBinary, append([]byte{92}, serverRandom...)); err != nil {
					logger.Warn(ctx, "RotateKey: Send: Error", zap.Error(err))
					return
				}
				mux.Unlock()
			}
		}()
		
		if err := next(ctx, sc); err != nil {
			logger.Warn(ctx, "Error proceeding to the next()", zap.Error(err))
		}
	})
}