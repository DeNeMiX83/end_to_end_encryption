package tcp

import (
	"bufio"
	"net"
)

type TCPHost struct {
	conn   net.Conn
	reader *bufio.Reader
}

func NewTCPHost(conn net.Conn) (*TCPHost, error) {
	reader := bufio.NewReader(conn)
	return &TCPHost{conn, reader}, nil
}

func (s *TCPHost) Send(data []byte) error {
	err := Send(s.conn, data)
	return err
}

func (s *TCPHost) Read() ([]byte, error) {
	bytes, err := Read(s.reader)
	return bytes, err
}

func (s *TCPHost) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
