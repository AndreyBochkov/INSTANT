package security

import (
	"nhooyr.io/websocket"
)

type SecureConn struct {
	conn		*websocket.Conn
	sessionKey	[]byte
	PeerID		int
	IKey		[]byte
}

type Payload struct {
	Type		byte
	Data		string
}
