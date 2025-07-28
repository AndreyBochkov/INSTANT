package transport

// import (
// 	"auth_service/pkg/postgres"
// 	socketio "github.com/graarh/golang-socketio"
// 	"context"
// 	"auth_service/pkg/logger"
// 	"crypto/rand"
// 	"go.uber.org/zap"
// 	iaes "auth_service/pkg/aes"
// 	"golang.org/x/crypto/curve25519"
// 	"crypto/sha256"
// 	"golang.org/x/crypto/hkdf"
// 	"encoding/json"
// 	jwt "github.com/golang-jwt/jwt/v5"
// 	"time"
// 	"golang.org/x/crypto/bcrypt"
// 	"github.com/jackc/pgconn"
// 	"errors"
// 	"github.com/jackc/pgx/v5"
// )

// func New(pool postgres.PGXPool, jwtKey string) Transport {
// 	return Transport{pool: pool, jwtKey: jwtKey, securemap: map[string][]byte{}}
// }

// func (t Transport) ReceivePublicKey(ctx context.Context, c *socketio.Channel, alicePublic []byte) { //hsclhl
// 	if len(alicePublic) != 32 {
// 		c.Emit("error", "Invalid request")
// 		return
// 	}

// 	bobPrivate := make([]byte, 32)
// 	rand.Read(bobPrivate)
// 	bobPublic, err := curve25519.X25519(bobPrivate, curve25519.Basepoint)
// 	if err != nil {
// 		logger.Warn(ctx, "Curve25519 bobPublic error", zap.Error(err))
// 		c.Emit("error", "Internal error")
// 		return
// 	}

// 	sharedPre, err := curve25519.X25519(bobPrivate, alicePublic)
// 	if err != nil {
// 		logger.Warn(ctx, "Curve25519 sharedPre error", zap.Error(err))
// 		c.Emit("error", "Internal error")
// 		return
// 	}

// 	serverRandom := make([]byte, 32)
// 	rand.Read(serverRandom)

// 	sharedMaster := make([]byte, 32)
// 	hkdf.New(sha256.New, sharedPre, serverRandom, nil).Read(sharedMaster)
	
// 	t.Lock()
// 	t.securemap[c.Id()] = sharedMaster
// 	t.Unlock()

// 	c.Emit("hssrhl", append(bobPublic, serverRandom...))
// }

// func (t Transport) Register(ctx context.Context, c *socketio.Channel, enc string) { //atregr
// 	jsonpayload, ok := t.decryptPayload(ctx, c, enc)
// 	if !ok {return}
// 	var payload RegisterRequest
// 	if err := json.Unmarshal([]byte(jsonpayload), &payload); err != nil {
// 		logger.Warn(ctx, "JSON decoder error", zap.Error(err), zap.String("request", jsonpayload))
// 		c.Emit("error", "Invalid request")
// 		return
// 	}
// 	if payload.Login == "" || payload.Password == "" {
// 		c.Emit("error", "Empty credentials")
// 		return
// 	}

// 	pass, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		logger.Warn(ctx, "Bcrypt error", zap.Error(err))
// 		c.Emit("error", "Internal error")
// 		return
// 	}

// 	err = t.pool.InsertUser(payload.Login, string(pass), payload.Name)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			// PostgreSQL SQLSTATE for unique_violation is "23505"
// 			if pgErr.Code == "23505" {
// 				c.Emit("error", "Duplicated login")
// 				return
// 			}
// 		}
// 		logger.Warn(ctx, "Postgres error", zap.Error(err))
// 		c.Emit("error", "Internal error")
// 		return
// 	}

// 	c.Emit("reregr", true)
// }

// func (t Transport) Login(ctx context.Context, c *socketio.Channel, enc string) { //atlogn
// 	jsonpayload, ok := t.decryptPayload(ctx, c, enc)
// 	if !ok {return}
// 	var payload LoginRequest
// 	if err := json.Unmarshal([]byte(jsonpayload), &payload); err != nil {
// 		logger.Warn(ctx, "JSON decoder error", zap.Error(err), zap.String("request", jsonpayload))
// 		c.Emit("error", "Invalid request")
// 		return
// 	}

// 	pass, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		logger.Warn(ctx, "Bcrypt error", zap.Error(err))
// 		c.Emit("error", "Internal error")
// 		return
// 	}
// 	id, name, err := t.pool.GetIDAndNameByLoginAndPassword(payload.Login, string(pass))
// 	if err != nil {
// 		if err == pgx.ErrNoRows {
// 			c.Emit("error", "Incorrect credentials")
// 			return
// 		} else {
// 			logger.Warn(ctx, "Postgres error", zap.Error(err))
// 			c.Emit("error", "Internal error")
// 			return
// 		}
// 	}

// 	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 		"iss": payload.Login,
// 		"sub": id,
// 		"exp": time.Now().Add(3*time.Hour).Unix(),
// 	}).SignedString([]byte(t.jwtKey))
// 	if err != nil {
// 		logger.Warn(ctx, "JWT error", zap.Error(err))
// 		c.Emit("error", "Internal error")
// 		return
// 	}

// 	resp, err := json.Marshal(LoginResponse{Name: name, Token: token})
// 	if err != nil {
// 		logger.Warn(ctx, "JSON encoder error", zap.Error(err))
// 		c.Emit("error", "Internal error")
// 		return
// 	}
// 	respstr, ok := t.encryptPayload(ctx, c, string(resp))
// 	if !ok {return}

// 	c.Emit("relogn", respstr)
// }

// func (t Transport) Disconnect(c *socketio.Channel) {
// 	if _, exists := t.securemap[c.Id()]; exists {
// 		t.Lock()
// 		delete(t.securemap, c.Id())
// 		t.Unlock()
// 	}
// }

// func (t Transport) decryptPayload(ctx context.Context, c *socketio.Channel, msg string) (string, bool) {
// 	aesKey, exists := t.securemap[c.Id()]
// 	if !exists {
// 		c.Emit("error", "Unauthorized")
// 		return "", false
// 	}
// 	payload, err := iaes.Decrypt(aesKey, msg)
// 	if err != nil {
// 		logger.Warn(ctx, "InstAES-256 decoding error. Message: " + msg, zap.Error(err))
// 		c.Emit("error", "Internal error")
// 		return "", false
// 	}
// 	return payload, true
// }

// func (t Transport) encryptPayload(ctx context.Context, c *socketio.Channel, msg string) (string, bool) {
// 	aesKey, exists := t.securemap[c.Id()]
// 	if !exists {
// 		c.Emit("error", "Unauthorized")
// 		return "", false
// 	}
// 	payload, err := iaes.Encrypt(aesKey, msg)
// 	if err != nil {
// 		logger.Warn(ctx, "InstAES-256 encoding error. Message: " + msg, zap.Error(err))
// 		c.Emit("error", "Internal error")
// 		return "", false
// 	}
// 	return payload, true
// }