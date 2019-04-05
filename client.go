package srp

import (
	"math/big"
)

type Client struct {
	N *big.Int
	I []byte
	p []byte
}

func NewClient(param *Params) Client {
	return &Client{
		N: gp.N
		g: gp.g
	}
}

func (c *Client) Hello(I string) []byte {
	c.I = []byte(I)
	return c.I
}

func (c *Client) Key() []byte {

}

func (c *Client) start() ([]byte, []byte) {

}