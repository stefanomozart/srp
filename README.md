# srp - an implementation of SRP-6a (as defined in RFC 5054)

[![GoDoc](https://godoc.org/github.com/stefanomozart/srp?status.svg)](https://godoc.org/github.com/stefanomozart/srp)
[![Go Report Card](https://goreportcard.com/badge/github.com/stefanomozart/srp)](https://goreportcard.com/report/github.com/stefanomozart/srp)

This package provides an implementation of SRP-6a, as defined in RFC 5054. The implementation uses
three main types:

* `srp.Client`: to create client side messages and values, such as user's salt **s** and verifier
  **v** (during user registration), and client private secret **a** and public key exchange value
  **A** (during user authentication);
* `srp.Server`: to create server side messages and values, such as server's private secret **b** 
  and public key exchange value **B**.
  
  Both, `srp.Client` and `srp.Server` will derive a shared secret **S** (called *premaster secret* in
  the RFC), a session key **K**, used to encrypt messages between both parties during that
  authenticated session. Also, both can compute evidence messages **M1** and **M2**;
* `srp.Params`: a structure to facilitate the definition of the three macro parameters for SRP
  protocol execution: the prime modulus **N** and a circular group generator **g** and a hash
  digest function.

Apart from those types, the package uses variable names that mach those defined in
[SRP-6a](https://tools.ietf.org/html/rfc5054#section-2.3):

| Name  | Type      | Description |
| ----- | --------- | ------------------------------------------------------------------------------------ |
| **N** | `big.Int` | safe prime (in the form 2p-1, withp prime), used as group modulus |
| **g** | `int64`   | a circular group generator in (2, N-1) |
| **s** | `[]bytes` | salt, a "random" sequence of bytes, generated during user registration |
| **b**, **B** | `[]bytes` | server's private and public key exchange values |
| **a**, **A** | `[]bytes` | client's private and public key exchange values |
| **I** | `[]bytes` | user identity |
| **P** | `[]bytes` | user password |
| **H** | `crypto.Hash` | a hash digest (one-way) function |
| **x** | `[]bytes` | a salted digest of the user's credentials (in the form `x := H(s | H(I | ":" | P))`) |
| **v** | `[]bytes` | user verifier (in the form `v := g^x % N`) |
| **PAD** | `func`  | Byte padding function |
| **k** | `[]bytes` | SRP-6a multiplier (`k := H(N | PAD(g))`) |
| **S** | `[]bytes` | premaster secret |
| **K** | `[]bytes` | shared session key |

This package also implements the evidence message extension defined in
[RFC 2945](https://tools.ietf.org/html/rfc2945). The variable names associated with this extension
are:

| Name  | Type      | Description |
| ----- | --------- | ----------- |
| **M1** | `[]bytes` | Evidence message, used to prove the client has calculated the correct session key |
| **M2** | `[]bytes` | Evidence message, used to prove the server has calculated the correct session key |

## The SRP Protocol

Package functions are organized to match protocol description in 
[RFC 5054](https://tools.ietf.org/html/rfc5054). So each protocol message will have a corresponding
method. Bellow a brief protocol descrition:

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

### User authentication

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
                                            (abort if A % N = 0)
                                            u := H(PAD(A) | PAD(B))
                                            S := (A * v^u)^b % N
                                            K := H(S)
      x := H(s | H(I | ":" | P))
      u := H(PAD(A) | PAD(B))
      k := H(N | PAD(g))
      S := (B - (k*g^x))^(a + (u*x)) % N
      K := H(S)

### Evidence messages (as defined in RFC 2945)

                        Client                       Server
                --------------                       ----------------
      M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K)
    Client Evidence (M1)                   -------->
                                                        (abort if M1 != H(H(N) XOR H(g) | H(U) | s | A | B | K))
                                                        M2 := H(A | M1 | K)
                                           <--------  Server Evidence (M2)
      (abort if M2 != H(A | M1 | K))

More details on the SRP protocol, it's definition and security proof, as well as the original article
where it was presented can be found on [The Stanford SRP Homepage](http://srp.stanford.edu).

 

## Implementation details

This implementation extends the default RF 5054 speficication, allowing the following customizations:

* It allows different choices of hash function, while the RFC speficication fixes the use of SHA-1;
* It allows the use of any group parameters (the prime modulus N and the group generator g);
* It provides simplified user registration and authentication protocol paths, eliminating messages
  used only for the exchange of protocol parameters.

### Registration protocol (simplified path)

This implementation provides a simplified execution path for the protocol. Assuming that both client
and server will use default parameters, we don't need the **Server Hello(N, g)** message. The
simplified execution path is:

```go
  import "github.com/stefanomozart/srp"
  
  // 1. Generate a random salt and compute the user's public verifier
  // ("I" and "P" are the original string form of user Identity and Password)
  client := srp.NewClient("I", "P")
  s, v, err := client.Registration()

  // 2. Then, send (I, s, v) to the server
```

### Registration protocol (standard)

In order to o run the user registration protocol with the standard **Server Hello(N, g)** message,
we need to follow these steps:

<table>
<tr>
<td>

**Client:**

```go
import "github.com/stefanomozart/srp"

// 1. Send user indentification (I []bytes) to the server

// 5. Receive protocol parameters from the server
// (N, g, h)

// 6. Create client instance with the parameters received
// from the server ("I" and "P" are the original string
// form of user Identity and Password)
params, err := srp.NewCustomParams(N, g, h);
client := srp.NewClientWithParams(params, "I", "P")
  
// 7. Generate a hashing salt a compute the user's public
// verifier
s, v, err := client.Registration()

// 8. Then, send (s, v) to the server
```

</td>
<td>

**Server:**

```go
import "github.com/stefanomozart/srp"

// 2. Receive user identity I

// 3. Load the chosen protocol execution parameters
// In this example, we use the 4096 bit-size group
// params from RFC 5054 Appendix A
params := srp.NewParams(4096, crypto.SHA3_256)
N := params.Modulus()
g := params.Generator()
h := params.HashFunction()

// 4. Then, send (N, g, h) to the client

// 9. Receive (s, v). Store (I, s, v)
```

</td>
</tr>
</table>

### Authentication protocol (simplified path)

The default execution path of the authentication protocol in our implementation is compliant to the
standard path described in RF 5054. We simplify the "Server Hello (N, g, s, B)" message, in order to
eliminate the need to send protocol execution parameters to the client.

<table>
<tr>
<td>

```go
import "github.com/stefanomozart/srp"

// 1. Create a srp.Client with the default
// parameters
client := srp.NewClient("I", "P")

// 2. Generate client secret `a` and key
// exchange value `A`
I, A := client.Hello()

// 3. Client sends (I, A) to the server over
// the network.

// 8. Client receives Server Hello (B, s)
// message and uses these values to compute
// a session key
K := client.SessionKey(B, s)

// 9. Additionally, the client can generate
// an evidence message
M1 := client.EvidenceMessage()

// 10. Then, send (M1) to the server
```

</td>
<td>

```go
import "github.com/stefanomozart/srp"

// 4. The server receives Client Hello (I, A)
// and searches the user database for the
// salt and verifier (s, v) corresponding to
// the indentity I
s, v := db.search(I)

// 5. Create a srp.Server using the default
// parameters
server := srp.NewServer(v, s)

// 6. Generate server's secret value b and
// public key exchange value B  
B, s := server.Hello()

// 7. Send Server Hello (B, s) to the
// client over the network.

// 8. Compute the session key
K := server.SessionKey(A)

// 10. Additionally, you may want to
// receive and check evidence message M1
err := server.VerifyEvidence(M1)
```

</td>
</tr>
</table>

### Authentication protocol (standard)

The main use case for the standard authentication protocol path would be the implementation of a SRP
server that accepts connections from clients built by third parties. In this case, you need the
complete *Server.Hello* message, as defined in RF 5054, that includes protocol operation parameters:
N, g and hash function.

Therefore, we include helper functions in the `srp.Params` type, so you can access those informations.
The standard execution path would be:

#### Client

```go
  import "github.com/stefanomozart/srp"
  
  // 1. Client Hello: send (I []byte - byte form of user identity) to the server

  // 7. Receive Server Standard Hello (N, g, h, s, B) from the server

  // 8. Create client instance with the parameters received from the server
  // ("I" and "P" are the original string form of user Identity and Password)
  params, err := srp.NewCustomParams(N, g, h);
  client := srp.NewClientWithParams(params, "I", "P")
  
  // 9. Generate client secret `a` and key exchange value `A`
  A := client.KeyExchange()

  // 10. Send Client Key Exchange (A) message to the server

  // 12. Use (B, s) received before to compute a session key
  K := client.SessionKey(B, s)

  // 13. Additionally, the client can generate an evidence message
  M1 := client.EvidenceMessage()

  // 14. Then, send (M1) to the server

  // 18. And receive the Server Evidence Message (M2), in order to
  // authenticate the server
  err := client.VerifyEvidence(M2)
```

#### Server

```go
  import "github.com/stefanomozart/srp"
  
  // 2. Receive Client Standard Hello (I) and search the user database for
  // the salt and verifier (s, v) corresponding to the indentity I
  s, v := db.search(I)

  // 3. Load the desired parameters. In this example we want to create a
  // new server using the 4096 bit-size group crypto.BLAKE2b_384 hash function
  params := srp.NewParams(4096, crypto.BLAKE2b_384)
  
  // 4. Create the server using the designated parameters
  server := srp.NewServerWithParams(params, s, v)

  // 5. Generate server secret b, compute server public key exchange value B
  // and retrieve the standard Server Hello message
  N, g, h, B := server.StandardHello()

  // 6. Send the standard Server Hello (N, g, h, s, B) message to the client

  // 11. receive Client Key Exchange (A) message from client and use the
  // received value to compute the sessio key
  K := server.SessionKey()
  
  // 15. Additionally, you may want to receive and check evidence message M1
  err := server.VerifyEvidence(M1)

  // 16. And generate server evidence, so the client may also authenticate the server
  M2 := server.EvidenceMessage()

  // 17. Send Server Evidence Message (M2)
```

 

### RFC 5054 Appendix A - Group Parameters

The RFC 5054 Appendix A brings a list of *Group Parameters*, with different bit sizes for the group
modulus. This package uses the 2048 bit-size group as default. It also uses the `crypto.SHA3_256` as
the default hashing function. In order to use diferent group or hash parameters, you can use a
`srp.Params` instance and pass it down when creating a `srp.Client` or `srp.Server` instance:

```go
  import "github.com/stefanomozart/srp"

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
  params, err := srp.NewCustomParams(hexEncodedStringValOfN, int64ValOfG, crypto.SHA3_256)
  client := srp.ClientWithParams(params, "userId", "userPwd")
  s, v, err := client.Registration()
```

### Custom hash function

You can choose any hash function that implements the crypto.Hash interface. We strongly advice for
the use of standard library implementations, specially those with longer digest sizes, such as
`crypto.SHA512`, `crypto.SHA3_256`, `crypto.SHA3_384`, `crypto.SHA3_512`, `crypto.BLAKE2b_384`
and `crypto.BLAKE2b_512`. The `crypto.SHA3_256` hash function is used as default in this package. In
order to set a different hash function, use a `srp.Params` structure to create your srp client or
server:

```go
  import "github.com/stefanomozart/srp"

  // Example: new client using the crypto.SHA3_512 hash function
  params := srp.NewParams(4096, crypto.SHA3_512)
  client := srp.NewClientWithParams(params, "userId", "userPwd")

  // Example: new server using the crypto.BLAKE2b_384 hash function
  params := srp.NewParams(4096, crypto.BLAKE2b_384)
  client := srp.NewServerWithParams(params, s, v)
```
