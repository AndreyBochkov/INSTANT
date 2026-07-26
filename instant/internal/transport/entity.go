package transport

import (
	"errors"
	"sync"

	p "instant_service/pkg/postgres"
	"instant_service/internal/security"
)

type Transport struct {
	sync.Mutex
	connmap			map[int](*security.SecureConn)

	pool			p.PGXPool
}

var (
	AuthorizedError = errors.New("Authorized")
	InternalJSONError = errors.New("Internal JSON error")
	InternalDBError = errors.New("Internal DB error")
	UnauthorizedError = errors.New("Unauthorized")
	MalformedEventError = errors.New("Malformed event")
)

type RegisterRequest struct { //11
	Login		string	`json:"login"`
	Img			[]byte	`json:"img"`
}

// type RegisterResponse p.User //51

type SearchRequest struct { //13
	Query		string	`json:"query"`
}

// type SearchResponse []p.User //53

type GetAdminsRequest struct { //14
	ChatID		int		`json:"chatid"`
}

type GetAdminsResponse struct { //54
	ChatID		int			`json:"chatid"`
	Admins		[]p.User 	`json:"admins"`
}

type GetListenersRequest struct { //15
	ChatID		int		`json:"chatid"`
}

type GetListenersResponse struct { //55
	ChatID		int			`json:"chatid"`
	Listeners	[]p.User	`json:"listeners"`
}

type GetQueuedRequest struct { //16
	ChatID		int		`json:"chatid"`
}

type GetQueuedResponse struct { //56
	ChatID		int			`json:"chatid"`
	Queued		[]p.User 	`json:"queued"`
}

type GetAllEventsRequest struct { //21
	FromID		int64	`json:"fromid"`
}

// type GetAllEventsResponse []p.Event //61

type GetChatEventsRequest struct { //22
	ToID		int64	`json:"toid"`
	ChatID		int		`json:"chatid"`
}

// type GetChatEventsResponse []p.Event //62

type EventRequest struct { //23
	Eventtype	string	`json:"type"`
	ChatID		int		`json:"chatid"`
	UserID		int		`json:"userid"`
	SubID		int64	`json:"subid"`
	Content		[]byte	`json:"content"`
}

type ChatData struct {
	Label		string	`json:"label"`
	Img			[]byte	`json:"img"`
}

// type EventResponse p.Event 63

type ReadMessageRequest struct { //31
	ChatID		int		`json:"chatid"`
	EventID		int64	`json:"eventid"`
}

// type ReadMessageResponse ReadMessageRequest // 71

type WhoReadThisRequest struct { //32
	ChatID		int		`json:"chatid"`
	EventID		int64	`json:"eventid"`
}

type Read struct {
	Ts			int64	`json:"ts"`
	UserID		int		`json:"userid"`
}
type WhoReadThisResponse struct { //72
	ChatID		int		`json:"chatid"`
	EventID		int64	`json:"eventid"`
	ReadList	[]Read	`json:"read"`
}

type WhoIsThisRequest struct { //17
	UserIDs		[]int	`json:"userids"`
}

// type WhoIsThisResponse []p.User //57

// type WhoAmIRequest [ackbyte] // 48

type ChangeIKeyRequest struct { //50
	New			[]byte	`json:"new"`
}

// type ChangeIKeyResponse [ackbyte] { //90

// type FATAL string //127
// type EmptyCredentials [ackbyte] //126
// type DuplicatedLogin [ackbyte] //125
// type LoginDenied [ackbyte] //123