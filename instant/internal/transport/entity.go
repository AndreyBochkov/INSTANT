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
	pool		postgres.PGXPool
	jwtKey		string
	version		int

	sync.Mutex
	connmap		map[int]SecureConn
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
// 	Token		string	`json:"token"`
// }

type SearchRequest struct { //6
	Query		string	`json:"query"`
}

type NewChatRequest struct { //7
	User2		int		`json:"user2"`
}

type GetMessagesRequest struct { //8
	ChatID		int		`json:"chatid"`
	Num			int		`json:"num"`
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

// =====RESPONSES SECTION=====

// type GetChatsResponse []postgres.Chat //10

// type SearchResponse []postgres.User //11

type NewChatResponse struct { //12
	ChatID		int		`json:"chatid"`
}

// type GetMessagesResponse []postgres.Message //13

type SendMessageResponse struct { //14
	MessageID	int64	`json:"messageid"`
	Ts			int64	`json:"ts"`
}

type GotMessageAck struct { //15
	ChatID		int		`json:"chatid"`
	MessageID	int64	`json:"messageid"`
	Ts			int64	`json:"ts"`
	Body		string	`json:"body"`
}

// type SyncResponse struct {
// 	Handshake	[]byte	`json:"handshake"`
// 	Messages	[]byte	`json:"messages"`
// }