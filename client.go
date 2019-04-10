package srp

import (
	"math/big"
)

// Client performs the computations required on the user side of the protocol
type Client struct {
	params *Params
	I      []byte
	P      []byte
	a      []byte
	A      []byte
}

// NewClient returns a new client, with the given credentials
func NewClient(I []byte, P []byte) *Client {
	p := NewDefaultParams()
	return &Client{
		params: p,
		I:      I,
		P:      P,
	}
}

// NewClientWithParams returns a new client, with the given credentials,
// using the custom group and hash parameters
func NewClientWithParams(p *Params, I []byte, P []byte) *Client {
	return &Client{
		params: p,
		I:      I,
		P:      P,
	}
}

// SetCredentials changes Client's credentials
func (c *Client) SetCredentials(I string, P string) []byte {
	c.I = []byte(I)
	c.P = []byte(P)
	return c.I
}

// GenerateA computes and returns the Client's chalange A (in the form A := g^a % N,
// for a := random()), used during the Key Exchange part of the protocol
func (c *Client) GenerateA() []byte {
	c.a = getRandomBytes(3)
	a := big.NewInt(0).SetBytes(c.a)
	g := big.NewInt(c.params.g)
	A := new(big.Int)
	c.A = A.Exp(g, a, c.params.N).Bytes()
	return c.A
}

// SessionKey computes and returns the SRP Session key, defined as
// S := (B - (k*g^x))^(a + (u*x)) % N
func (c *Client) SessionKey() ([]byte, []byte) {
	return nil, nil
}

//var n int64 = 97
//s := strconv.FormatInt(n, 16) // s == "61" (hexadecimal)
