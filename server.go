package srp

import (
	"math/big"
)

// Server performs the server side computations of the SRP protocol
type Server struct {
	params *Params
	b      []byte
	B      []byte
	v      []byte
	s      []byte
	S      []byte
}

// NewServer creates a new server instance for the given credentials
func NewServer(v, s string) *Server {
	p := NewDefaultParams()
	return &Server{
		params: p,
		v:      []byte(v),
		s:      []byte(s),
	}
}

// NewServerWithParams creates a new server instance for the given credentials
// using the custom group and hash parameters
func NewServerWithParams(p *Params, v, s string) *Server {
	return &Server{
		params: p,
		v:      []byte(v),
		s:      []byte(s),
	}
}

// GenerateB generates the server's secret b and its public masked value B.
// Then, returns the bytes of B
func (s *Server) GenerateB() []byte {
	s.b = getRandomBytes(3)
	b := big.NewInt(0).SetBytes(s.b)
	g := big.NewInt(s.params.g)
	s.B = big.NewInt(0).Exp(g, b, s.params.N).Bytes()

	return s.B
}
