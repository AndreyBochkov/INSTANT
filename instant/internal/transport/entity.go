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

type parsedHSPayload struct {
	id				int
	ts				int64
	iKey			[]byte
	bobPublic		[]byte
	sharedPre		[]byte
}

type SecureConn struct {
	conn		*websocket.Conn
	sessionKey	[]byte
}

type Transport struct {
	pool				postgres.PGXPool
	version				int
	rotationInterval	int

	sync.Mutex
	connmap				map[int]SecureConn
}

type RegisterRequest struct { //17
	Login		string	`json:"login"`
}

// type RegisterResponse [ackbyte] //18

// =====REQUESTS SECTION=====

// type GetChatsRequest [ackbyte] { //11

type SearchRequest struct { //12
	Query		string	`json:"query"`
}

type NewChatRequest struct { //13
	User2		int		`json:"user2"`
}

type GetMessagesRequest struct { //14
	ChatID		int		`json:"chatid"`
	Offset		int		`json:"offset"`
}

type SendMessageRequest struct { //15
	Receiver	int		`json:"receiver"`
	ChatID		int		`json:"chatid"`
	Body		string	`json:"body"`
}

type SyncRequest struct { //http
	Handshake	[]byte	`json:"handshake"`
}

type ChangeIKeyRequest struct { //16
	New			[]byte	`json:"new"`
}

// =====RESPONSES SECTION=====

// type GetChatsResponse []postgres.Chat //51

// type SearchResponse []postgres.User //52

// type NewChatResponse postgres.Chat //53

type GetMessagesResponse struct { //54
	ChatID		int					`json:"chatid"`
	Messages	[]postgres.Message	`json:"messages"`
}

// type SendMessageResponse postgres.SyncMessage //55

// type ChangePasswordResponse [ackbyte] { //56

// type GotMessageAck postgres.SyncMessage //91

// type SyncResponse struct { //http
// 	Handshake	[]byte	`json:"handshake"`
// 	Messages	[]byte	`json:"messages"`
// }