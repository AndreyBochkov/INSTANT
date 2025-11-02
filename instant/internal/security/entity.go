package security

import (
	"nhooyr.io/websocket"
)

var (
	nilPayload = Payload{0, ""}
)

type SecureConn struct {
	conn		*websocket.Conn
	sessionKey	[]byte
	peerID		int
	iKey		[]byte
}

type Payload struct {
	Type		byte
	Data		string
}
