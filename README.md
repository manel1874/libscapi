# LIBSCAPI - The Secure Computation API

libscapi is the Open source C++ library for implementing high performance secure two-party and multiparty computation protocols (SCAPI stands for the "Secure Computation API"). It provides a reliable, efficient, and highly flexible cryptographic infrastructure.

Libscapi is developed by [Bar Ilan University Cryptography Research Group](http://crypto.biu.ac.il/). The goal of libscapi is to promote research by Academy and Industry practitioners in this field by providing:

- A consistent API over Primitives, Mid-Layer Protocols, Interactive Mid-Layer Protocols and Communication Channels, simplifying the development and evaluation fo new protocols. We focus on keeping libscapi easy to build and use.
- Integrating best performance open-source implementations by other Academy Research Institutes.  
- High Performance implementation on standard Linux & Intelx64 Architecture. We use modern techniques like Intel Intrinsics  Instructions, Pipelining and TCP optimizations.  

## libscapi Modules
- __Primitives__: Dlog, Cryptographic Hash Function, HMAC and KDF, Pseudorandom Functions and Permutations, Pseudo Random Generator, Trapdoor Permutation, Random Oracle (to be elaborated)
- __Mid-layer protocols__: Currently includes Public Key Encryption Schemes: Cramer-Shoup, Damgard-Jurik, El-Gamal
- __Interactive Mid-layer protocols__: Sigma Protocols, Zero Knowledge Proofs, Commitment Schemes (to be elaborated)
- __OT Extension__ - Semi-Honest and Malicious 
- __Circuits__: To be elaborated
- __Communication Channel__: To be elaborated

## License information
Libscapi is released under the MIT open source license. However, some of the libraries we use have different licenses. For further information pleare refer to [LICENSE.MD](build_scripts/LICENSE.MD)

## Documentation

Go to http://biulibscapi.readthedocs.org/ for a detailed explanations of our implementation.

## Installing libscapi

Libscapi supports this OSs (with C++11/C++14):
- Ubuntu 14.04/16.04/18.04 LTS
- CentOS 7.3
- Mac OSx High Sierra 10.13  

For detailed instructions, see [INSTALL.md](build_scripts/INSTALL.md)

## Libraries used by libscapi

### Implementations by other Academic Institutes

##### Cryptography Research at Oragon State University : LibOTE A fast, portable, and easy to use Oblivious Transfer Libary
[https://github.com/osu-crypto/libOTe](https://github.com/osu-crypto/libOTe)

##### University of Bristol: Advanced Protocols for Real-world Implementation of Computational Oblivious Transfers
[https://github.com/bristolcrypto/apricot](https://github.com/bristolcrypto/apricot)

##### Tung Chou and Claudio Orlandi: The Simplest Oblivious Transfer Protocol
[http://users-cs.au.dk/orlandi/simpleOT/](http://users-cs.au.dk/orlandi/simpleOT/)

### Math and General Purpose Libraries

##### OpenSSL
[https://www.openssl.org/](https://www.openssl.org/)

 OpenSSL is an open source project that provides a robust, commercial-grade, and full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols. It is also a general-purpose cryptography library. For more information about the team and community around the project, or to start making your own contributions, start with the community page. To get the latest news, download the source, and so on, please see the sidebar or the buttons at the top of every page.

##### The GNU Multiple Precision Arithmetic Library (GMP)
[https://gmplib.org/](https://gmplib.org/)

GMP is a free library for arbitrary precision arithmetic, operating on signed integers, rational numbers, and floating-point numbers. There is no practical limit to the precision except the ones implied by the available memory in the machine GMP runs on. GMP has a rich set of functions, and the functions have a regular interface.
The main target applications for GMP are cryptography applications and research, Internet security applications, algebra systems, computational algebra research, etc.

##### NTL: A Library for doing Number Theory- Victor Shoup
[ttp://www.shoup.net/ntl/](http://www.shoup.net/ntl/)

NTL is a high-performance, portable C++ library providing data structures and algorithms for manipulating signed, arbitrary length integers, and for vectors, matrices, and polynomials over the integers and over finite fields.On modern platforms supporting C++11, NTL can be compiled in thread safe and exception safe modes. 

##### Boost 1.64
[http://www.boost.org/](http://www.boost.org/)

Boost provides free peer-reviewed portable C++ source libraries. We emphasize libraries that work well with the C++ Standard Library. Boost libraries are intended to be widely useful, and usable across a broad spectrum of applications

