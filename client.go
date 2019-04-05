package srp

type Client {
	N big
	I []byte
	p []byte
}

func NewClient(gp *GroupParams) Client {
	return &Client{
		N: gp.N
		g: gp.g
	}
}

func (*Client) verifier() []byte {

}

func (* Client) start() ([]byte, []byte) {

}