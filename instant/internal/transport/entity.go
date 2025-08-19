package transport

import (
	"nhooyr.io/websocket"

	"errors"
	"sync"

	"instant_service/pkg/postgres"
)

var (
	handshakeFault = errors.New("Invalid handshake pattern")
	tokenExpiredError = errors.New("Token expired")
	invalidVersionError = errors.New("Invalid version")
	verificationError = errors.New("Verification error")
)

type SecureConn struct {
	conn		*websocket.Conn
	sessionKey	[]byte
}

type Transport struct {
	pool				postgres.PGXPool
	jwtKey				string
	version				int
	rotationInterval	int

	sync.Mutex
	connmap				map[int]SecureConn
}

type RegisterRequest struct {
	Login		string	`json:"login"`
	Password	string	`json:"password"`
	Name		string	`json:"name"`
}

type LoginRequest struct {
	Login		string	`json:"login"`
	Password	string	`json:"password"`
}

type LoginResponse struct {
	Name		string	`json:"name"`
	Token		string	`json:"token"`
}

// =====REQUESTS SECTION=====

// type GetChatsRequest struct { //5
// }

type SearchRequest struct { //6
	Query		string	`json:"query"`
}

type NewChatRequest struct { //7
	User2		int		`json:"user2"`
}

type GetMessagesRequest struct { //8
	ChatID		int		`json:"chatid"`
	Offset		int		`json:"offset"`
}

type SendMessageRequest struct { //9
	Receiver	int		`json:"receiver"`
	ChatID		int		`json:"chatid"`
	Body		string	`json:"body"`
}

type SyncRequest struct { //http
	Handshake	[]byte	`json:"handshake"`
	After		int64	`json:"after"`
}

type ChangePasswordRequest struct { //16
	Old			string	`json:"old"`
	New			string	`json:"new"`
}

// =====RESPONSES SECTION=====

// type GetChatsResponse []postgres.Chat //10

// type SearchResponse []postgres.User //11

// type NewChatResponse postgres.Chat //12

type GetMessagesResponse struct { //13
	ChatID		int					`json:"chatid"`
	Messages	[]postgres.Message	`json:"messages"`
}

// type SendMessageResponse postgres.SyncMessage //14

// type GotMessageAck postgres.SyncMessage //15

// type SyncResponse struct { //http
// 	Handshake	[]byte	`json:"handshake"`
// 	Messages	[]byte	`json:"messages"`
// }

// type ChangePasswordResponse struct { //17
// }