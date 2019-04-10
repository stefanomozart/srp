# srp - an implementation of SRP-6a (as defined in RFC 5054)

[![GoDoc](https://godoc.org/github.com/stefanomozart/srp?status.svg)](https://godoc.org/github.com/stefanomozart/srp)
[![Go Report Card](https://goreportcard.com/badge/github.com/stefanomozart/srp)](https://goreportcard.com/report/github.com/stefanomozart/srp)

This package provides an implementation of SRP-6a, as defined in RFC 5054. This implementation
uses three main types:

* `srp.Client`: to create client side messages, user's verifier **v** and salt **s** (during user
registration), as client private key **a** and public challenge **A** (during user authentication);
* `srp.Server`: to create server side messages: authentication challenge **B**, shared session key
* `srp.Params`: a structure to facilitate the definition of the three macro parameters for SRP protocol
execution: the prime modulus **N** and a circular group generator **g** and a hash digest
function.

Apart from those types, the package uses variable names that mach those defined in
[SRP-6a](https://tools.ietf.org/html/rfc5054#section-2.3):

| Name  | Type      | Description |
| ----- | --------- | ----------- |
| **N** | `big.Int` | safe prime (in the form 2p-1, withp prime), used as group modulus |
| **g** | `int64`   | a circular group generator in (2,N-1) |
| **s** | `[]bytes` | salt, a "random" sequence of bytes, generated during user registration |
| **B**, **b** | `[]bytes` | server's public and private values |
| **A**, **a** `[]bytes` | client's public and private values |
| **I** | `[]bytes` | user identity |
| **P** | `[]bytes` | user password |
| **H** | `crypto.H |sh`: a hash digest (one-way) function |
| **x** | `[]bytes` | a salted digest of the user's credentials (in the form `x := H(s | H(I | ":" | P))`) |
| **v** | `[]bytes` | user verifier (in the form `v := g^x % N`) |
| **PAD** | `func`  | Byte padding function |
| **k** | `[]bytes` | SRP-6a multiplier (`k := H(N | PAD(g))`) |
| **S** | `[]bytes` | session shared key |

## The SRP Protocol

Package functions are organized to match protocol description in RFC 5054 (https://tools.ietf.org/html/rfc5054).
So each protocol message will have a corresponding method. Bellow a brief protocol descrition:

### User registration

                        Client          Server
                --------------          ----------------
    Client Hello (I)           -------->
                               <--------    Server Hello (N, g)
    s := random()
    x := H(s | H(I | ":" | P))
    v := g^x % N
    Client Registration (s, v) -------->
                                            (store I, s, v)

To performe those protocol steps using this package:

```go
    import "github.com/opencoff/go-srp"

    client := srp.NewClient("userId", "userPassword")
    s, v, err := client.Registration()
    // Then, send s and v to the server
```

### User authentication (simplified implementation)

                        Client          Server
                --------------          ----------------
    Client Hello (I)            -------->
                                            (Find s and v corresponding to I)
                                            b := random()
                                            k := H(N | PAD(g))
                                            B := (k*v + g^b) % N
                              <--------   Server Hello (N, g, s, B)
    (abort if B % N = 0)
    a := random()
    A := g^a % N
    Client Key Exchange (A)     -------->
                                            u := H(PAD(A) | PAD(B))
                                            S := (A * v^u)^b % N
    x := H(s | H(I | ":" | P))
    u := H(PAD(A) | PAD(B))
    k := H(N | PAD(g))
    S := (B - (k*g^x))^(a + (u*x)) % N

<table>
<tr>
<td>

```go
  import "github.com/opencoff/go-srp"

  // 1. Create a srp.Client with the default parameters
  // (assumes the server will use the same parameters)
  client := srp.NewClient("userId", "userPassword")
  I := client.Hello()

  // 2. Client sends I to the server over the network.
  
  // 3. The server should look up the user database for the the salt s
  // and verifier v corresponding to the indentity I
  s, v := db.VerifierLookup(I)

  // 4. Create a srp.Server using the default parameters
  server := srp.NewServer(v, s)

  // 5. Generate the servers secret value b and public challenge B  
  B := server.GenerateB()

  // 6. Send B to the client over the network.
  
  // 7. The client the uses this value to compute a session key
  A := client.GenerateA()
    sessioKey := client.SessionKey(A, B)

    v, s, err := cli.GenerateV()
    // Then, send s and v to the server
```

</td>
<td>

```go
  import "github.com/opencoff/go-srp"

  // 3. The server should look up the user database for the the salt s
  // and verifier v corresponding to the indentity I
  s, v := db.VerifierLookup(I)

  // 4. Create a srp.Server using the default parameters
  server := srp.NewServer(v, s)

  // 5. Generate the servers secret value b and public challenge B  
  B := server.GenerateB()
```

</td>
</tr>
</table>


### Server authentication

                     Client       Server
    Client Hello (I)      -------->

```go
  serverM1 := server.GenerateM1()

  clientM1 := cliente.GenerateM1()
```

## Implementation details

This implementation extends the default RF 5054 speficication, allowing the following
customizations:

* We allow different choices of Hash function, while the RFC speficication fixes the use of SHA-1
* We allow the use of any group parameters (the prime modulus N and the group generator g)

### RFC 5054 Appendix A - Group Parameters

The RFC 5054 Appendix A brings a list of *Group Parameters*, with different bit sizes for
the group modulus. This package uses the 2048 bit-size group as default. It also uses the
 In order to use
diferent group parameter, you can use a `srp.Params` instance and inform it when creating
a `srp.Client` or `srp.Server` instance:

```go
  // Example: using the RFC 4096 bit-size group params to generate a user verifier
  params := srp.NewParams(4096, crypto.SHA256)
  client := srp.NewClientWithParams(params, "userId", "userPwd")
  s, v, err := client.Registration()

  // Likewise, you can have a server with the RFC 5054 6144 bit-size group params
  // just make sure to use the same parameters both on client and server sides
  params := srp.NewParams(5054, crypto.SHA256)
  server := srp.NewServerWithParams(params, s, v)
```

### Custom group parameters

Additionaly, you can use group parameters not defined in RFC 5054. Use this feature
with caution, as a non-safe prime may weaken your implementation.

```go
  // Example: using custom group parameters
  params := srp.NewCustomParams(hexEncodedStringValOfN, int64ValOfG, crypto.SHA256)
  client := srp.ClientWithParams(params, "userId", "userPwd")
  s, v, err := client.Registration()
```

### Custom hash function

You can choose any hash function that implements the crypto.Hash interface. We strongly advice
for the use of standard library implementations, specially those with longer digest sizes, such
as `crypto.SHA512`, `crypto.SHA3_256`, `crypto.SHA3_384`, , `crypto.SHA3_512`, `crypto.BLAKE2b_384`
and `crypto.BLAKE2b_512`. The `crypto.SHA3_256` hash function is used as default in this package.
In order to set a different hash function, use a `srp.Params` structure to create your srp client 
or server:

```go
  // Example: new client using the crypto.SHA3_512 hash function
  params := srp.NewParams(4096, crypto.SHA3_512)
  client := srp.NewClientWithParams(params, "userId", "userPwd")

  // Example: new server using the crypto.BLAKE2b_384 hash function
  params := srp.NewParams(4096, crypto.BLAKE2b_384)
  client := srp.NewServerWithParams(params, s, v)
```

### Alternative protocol execution, when using custom parameters

The main use case would be the implementation of a SRP server that accepts connections
from clients built by third parties. In the case, you may want a Server.Hello message as
defined in RF 5054, that includes protocol operation the parameters: N, g and hash function.
Therefore, we include helper functions so you can access those information:

```go
  // Example: new server using the crypto.BLAKE2b_384 hash function
  params := srp.NewParams(4096, crypto.BLAKE2b_384)
  client := srp.NewServerWithParams(params, s, v)

  N := params.Modulus() // returns the bytes of the N parameter
  g := params.Generator() // returns the g parameter

  // Send the unkown client the complete server hello <N, g, crypto.BLAKE2b_384
```