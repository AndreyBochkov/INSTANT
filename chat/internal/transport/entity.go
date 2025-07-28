package transport

import (
	"chat_service/pkg/postgres"
	"nhooyr.io/websocket"
)

var (
	tokenExpiredError = errors.New("Expired")
)

type Transport struct {
	pool		postgres.PGXPool
	jwtKey		string
}

// =====REQUESTS SECTION=====

type GetChatsRequest struct { //5
	Token		string	`json:"token"`
}

type SearchRequest struct { //6
	Token		string	`json:"token"`
	Query		string	`json:"query"`
}

type NewChatRequest struct { //7
	Token		string	`json:"token"`
	User2		int		`json:"user2"`
}

type GetMessagesRequest struct { //8
	Token		string	`json:"token"`
	ChatID		int		`json:"chatid"`
	Num			int		`json:"num"`
	Offset		int		`json:"offset"`
}

type SendMessageRequest struct { //9
	Token		string	`json:"token"`
	ChatID		int		`json:"chatid"`
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
}