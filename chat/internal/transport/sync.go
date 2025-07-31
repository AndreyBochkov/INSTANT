package transport

import (
	"context"
	"net/http"
	"encoding/json"
	"errors"

	"nhooyr.io/websocket"
	"go.uber.org/zap"

	"chat_service/pkg/logger"
	iaes "chat_service/pkg/aes"
)

func (t Transport) SyncWSHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		OriginPatterns: []string{"*"},
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
		return
	}

	for {
		_, enc, err := conn.Read(context.Background())
		if err != nil {
			return
		}

		payload, err := iaes.Decrypt(sessionKey, enc)
		if err != nil {
			logger.Warn(ctx, "InstAES decoding error", zap.Error(err))
			continue
		}

		var result []byte

		switch enc[0] {
		case 16:
			var req RegisterTokenRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				logger.Warn(ctx, "JSON decoder error", zap.Error(err))
				return
			}
			id, login, err := t.parseToken(req.Token)
			if err != nil {
				if errors.Is(err, tokenExpiredError) {
					result = append([]byte{127}, []byte("Unauthorized")...)
					// ret [127, U, n, a, u, ...]
					break
				}
				logger.Warn(ctx, "Token error", zap.Error(err))
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
			logger.Info(ctx, "Connected", zap.Int("id", id))
			defer func() {
				t.Lock()
				delete(t.connmap, id)
				t.Unlock()
				logger.Info(ctx, "Disconnected", zap.Int("id", id))
			}()
			result = []byte{17}
			// ret [17]
			break
		default:
			logger.Warn(ctx, "Invalid payload: " + string(payload), zap.Int("invalidMessageType", int(enc[0])))
			return
		}

		resp := []byte{}
		if len(result) > 1 {
			resp, err = iaes.Encrypt(sessionKey, result[1:])
			if err != nil {
				logger.Warn(ctx, "Encryption error", zap.Error(err))
				continue
			}
		}

		if err := conn.Write(context.Background(), websocket.MessageBinary, append([]byte{result[0]}, resp...)); err != nil {
			return
		}
	}
}
