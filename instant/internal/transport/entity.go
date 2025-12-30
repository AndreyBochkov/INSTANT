package transport

import (
	"errors"
	"sync"

	"instant_service/pkg/postgres"
	"instant_service/internal/security"
)

type Transport struct {
	sync.Mutex
	connmap				map[int](*security.SecureConn)

	pool				postgres.PGXPool
}

var (
	AuthorizedError = errors.New("Authorized")
	InternalJSONError = errors.New("Internal JSON error")
	InternalDBError = errors.New("Internal DB error")
	UnauthorizedError = errors.New("Unauthorized")
)

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

// type GetAlertsRequest [ackbyte] //49

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

type SyncMessage struct { //57 SendMessageResponse
	ChatID		int		`json:"chatid"`
	MessageID	int64	`json:"messageid"`
	Ts			int64	`json:"ts"`
	Body		string	`json:"body"`
	Sender		int		`json:"sender"`
}

// type GetAlertsResponse []postgres.Alert //89

// type ChangeIKeyResponse [ackbyte] { //90

type WhoAmI struct { //91
	Login		string	`json:"login"`
	Id			int		`json:"id"`
}

// type FATAL string //127
// type EmptyCredentials [ackbyte] //126
// type DuplicatedLogin [ackbyte] //125
// type AccessDenied [ackbyte] //124
// type LoginDenied [ackbyte] //123