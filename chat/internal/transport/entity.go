package transport

import (
	"nhooyr.io/websocket"

	"errors"
	"sync"

	"chat_service/pkg/postgres"
)

var (
	tokenExpiredError = errors.New("Token expired")
	invalidVersionError = errors.New("Invalid version")
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

type RegisterTokenRequest struct { //16
	Token		string	`json:"token"`
}

type SyncRequest struct { //http
	UserID		int		`json:"id"`
	EncToken	string	`json:"enctoken"`
	Since		int64	`json:"since"`
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

type SyncResponse struct {
	EncData		string	`json:"encdata"`
}