package transport

import (
	"nhooyr.io/websocket"

	"errors"
	"sync"

	"instant_service/pkg/postgres"
)

type Transport struct {
	sync.Mutex
	connmap				map[int](*SecureConn)

	pool				postgres.PGXPool
}

type RegisterRequest struct { //11
	Login		string	`json:"login"`
}

// type GetChatsRequest [ackbyte] { //12

type SearchRequest struct { //13
	Query		string	`json:"query"`
}

type GetPropertiesRequest struct { // 14
	ChatID		int		`json:"chatid"`
}

type NewChatRequest struct { //15
	Admins		[]int	`json:"admins"`
	Listeners	[]int	`json:"listeners"`
	Label		string	`json:"label"`
}

type GetMessagesRequest struct { //16
	ChatID		int		`json:"chatid"`
	Offset		int		`json:"offset"`
}

type SendMessageRequest struct { //17
	ChatID		int		`json:"chatid"`
	Body		string	`json:"body"`
}

type ChangeIKeyRequest struct { //50
	New			[]byte	`json:"new"`
}

// type RegisterResponse [ackbyte] //51

// type GetChatsResponse []postgres.Chat //52

// type SearchResponse []postgres.User //53

type GetPropertiesResponse struct { // 54
	ChatID		int					`json:"chatid"`
	Admins		[]postgres.User		`json:"admins"`
	Listeners	[]postgres.User		`json:"listeners"`
}

// type NewChatResponse postgres.Chat //55

type GetMessagesResponse struct { //56
	ChatID		int					`json:"chatid"`
	Messages	[]postgres.Message	`json:"messages"`
}

type SyncMessage struct { //57 SendMessageResponse //91 GotMessageAck
	ChatID		int		`json:"chatid"`
	MessageID	int64	`json:"messageid"`
	Ts			int64	`json:"ts"`
	Body		string	`json:"body"`
	Sender		int		`json:"sender"`
}

// type ChangeIKeyResponse [ackbyte] { //90