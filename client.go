package srp

import (
	"math/big"
)

// Client performs the computations required on the user side of the protocol
type Client struct {
	N *big.Int
	I []byte
	p []byte
}

// NewClient returns a new client
func NewClient(param *Params) Client {
	return &Client{
		N: param.N,
		g: param.g,
	}
}

func (c *Client) Hello(I string) []byte {
	c.I = []byte(I)
	return c.I
}

func (c *Client) GenerateA() []byte {

}

func (c *Client) GenerateKey() ([]byte, []byte) {

}
