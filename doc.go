// Copyright 2019 Stefano Mozart (stefanomozart@ieee.org)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package `srp` provides an implementation of SRP-6a, as defined in RFC 5054. There
are three main types: Params, Client and Server.

Apart from those types, the package uses variable names that mach those defined in
[SRP-6](https://tools.ietf.org/html/rfc5054#section-2.3):
	N big.Int, g int: group parameters (prime and generator)
	s []bytes: salt
	B, b []bytes: server's public and private values
	A, a []bytes: client's public and private values
	I []bytes: user "identity"
	P []bytes: password
	v []bytes: verifier (in the form `v := g^x % N`, x is defined below)
	H crypto.Hash: hash function of choice
	k []bytes: SRP-6a multiplier (k = H(N | PAD(g)))

	x := H(s | H(I | ":" | P))
	v := g^x % N

Package functions are organized to match protocol description in RFC 5054 (https://tools.ietf.org/html/rfc5054). So each protocol message will have a corresponding method. Bellow a brief
protocol descrition:
# User registration
						Client			Server
	Client Hello (I)			-------->
								<--------	Server Hello (N, g)
	s := random()
    x := H(s | H(I | ":" | P))
	v := g^x % N
	Client registration (s, v)	-------->
											(store I, s, v)

# User authentication
						Client			Server
	Client Hello (I)			-------->
											(Find s and v corresponding to I)
											b := random()
											k := H(N | PAD(g))
											B := (k*v + g^b) % N
								<--------	Server Hello (N, g, k, s, B)
	(abort if B % N = 0)
	a := random()
	A := g^a % N
	Client Key Exchange (A)		-------->
											u := H(PAD(A) | PAD(B))
											S := (A*v^u)^b % N
	x := H(s | H(I | ":" | P))
	u := H(PAD(A) | PAD(B))
	S := (B - (k*g^x))^(a + (u*x)) % N


Differences between this implementation and RFC 5054:
* We allow differente choices of Hash function, while the RFC defines SHA-1
* W
*/
package srp
