# Libscapi
libscapi is the C++ high performance version of scapi (Secure Multiparty Computation API). We are in beta,  release of first version is expected by 1 August 2016. 
The goal of libscapi is to promote research by Academy and Industry practitioners in this field by providing:

- A consistent API over Primitives, Mid-Layer Protocols, Interactive Mid-Layer Protocols and Communictaion Channels, simplifying the development and evaluation fo new protocols. We focus on keeping libscapi easy to build and use.
- Integrating best performance open-source implementations by other Academy Research Institutets.  
- High Performance implementation on standard Linux & Intelx64 Architecture. We use modern techniques like Intel Intrinsics Instructions, Pipelining and TCP optimizations. However, we avoid using techinques that are too advanced or not available on common platforms (such as Intel AVX-512 and DPDK, GPGPU exc).   
- Provide a common platfrom for benchmarking different alogirthms and implementations

## License information
Libscapi is released under the MIT open source license. However, some of the libraries we use have different licenses. Fo further information pleare refer to [LICENSE.MD](LICENSE.MD)

##Installing libscapi

Libscapi has is tested on Ubuntu 14.04 and should run on all major versions of Linux. It also executes on Windows 8.1/10 but with performance limitations. Interally we use the Windows option for development only. All tests execute on Linux.
Mac OSX has not been tested so far. 
For detailed instructions, see [INSTALL.MD](INSTALL.MD)

## Libraries used by libscapi

### Math and General Purpose Libraries

##### OpenSSL
[](https://www.openssl.org/)
##### The GNU Multiple Precision Arithmetic Library (GMP)
[](https://gmplib.org/)
##### NTL: A Library for doing Number Theory- Victor Shoup
[](http://www.shoup.net/ntl/)
##### MIRACL Cryptographic SDK
[](https://github.com/miracl/MIRACL)
##### Boost 1.60
[](http://www.boost.org/)
##### Cereal C++ Serialization Library
[](http://uscilab.github.io/cereal/)

### Implementations by other Academic Institutes

##### Engineering Cryptographic Protocols Group at TU Darmstadt OT Extension
[](https://github.com/encryptogroup/OTExtension)

Implementation of the passive secure OT extension protocol of [1] and the active secure OT extension protocols of [2] and [3]. Implements the general OT (G_OT), correlated OT (C_OT), global correlated OT (GC_OT), sender random OT (SR_OT), and receiver random OT (RR_OT) (Definitions of the functionalities will follow). Implements the base-OTs by Naor-Pinkas [4], Peikert-Vaikuntanathan-Waters [5], and Chou-Orlandi [6]. The code is based on the OT extension implementation of [7] and uses the MIRACL libary [8] for elliptic curve arithmetic. Update: Implemented 1-out-of-2 OT from the 1-out-of-N OT extension of [10].




