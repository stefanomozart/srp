package srp

import (
	"crypto"
	"math/big"
)

// Client performs the computations required on the user side of the protocol
type Client struct {
	N *big.Int
	g int
	h crypto.Hash
	I []byte
	P []byte
}

// NewClient returns a new client
func NewClient(param *Params) *Client {
	return &Client{
		N: param.N,
		g: param.g,
		h: param.H,
	}
}

func (c *Client) SetCredentials(I string, P string) []byte {
	c.I = []byte(I)
	c.P = []byte(P)
	return c.I
}

func (c *Client) GenerateA() []byte {
	c.a = getRandomBytes(3)
	c.A = big.NewInt(c.g).pow(big.NewInt(0).SetBytes(c.a)).mod(c.N)
	return c.A
}

//B, ok1 := big.NewInt(0).SetString(v[1], 16)
func (c *Client) GenerateKey() ([]byte, []byte) {
	return nil, nil
}

func (c *Client) H(a []byte) []byte {
	h := c.h.New()
	for _, z := range a {
		h.Write(z)
	}
	return h.Sum(nil)
}
