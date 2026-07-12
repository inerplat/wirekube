package relay

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketConn adapts binary WebSocket messages to the byte-stream contract
// used by the relay framing protocol.
type WebSocketConn struct {
	conn *websocket.Conn

	readMu  sync.Mutex
	reader  io.Reader
	writeMu sync.Mutex
}

func NewWebSocketConn(conn *websocket.Conn) *WebSocketConn {
	return &WebSocketConn{conn: conn}
}

func (c *WebSocketConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.reader != nil {
			n, err := c.reader.Read(p)
			if err == nil {
				return n, nil
			}
			if err != io.EOF {
				return n, err
			}
			c.reader = nil
			if n > 0 {
				return n, nil
			}
		}

		messageType, reader, err := c.conn.NextReader()
		if err != nil {
			return 0, err
		}
		if messageType != websocket.BinaryMessage {
			continue
		}
		c.reader = reader
	}
}

func (c *WebSocketConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *WebSocketConn) Close() error                       { return c.conn.Close() }
func (c *WebSocketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *WebSocketConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *WebSocketConn) SetDeadline(t time.Time) error      { return c.conn.UnderlyingConn().SetDeadline(t) }
func (c *WebSocketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *WebSocketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
