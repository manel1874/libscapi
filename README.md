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

### Ubuntu 14.04LTS

#### Prerequisites
- sudo apt-get update
- sudo apt-get install git
- sudo apt-get install -y build-essential

#### Installing boost
- wget -O boost_1_60_0.tar.bz2 http://sourceforge.net/projects/boost/files/boost/1.60.0/boost_1_60_0.tar.bz2/download
- tar --bzip2 -xf boost_1_60_0.tar.bz2
-  ./bootstrap.sh
-  ./b2 
- sudo ldconfig ~/boost_1_60_0/stage/lib/

#### Installing OpenSSL
- sudo apt-get install libssl-ocaml-dev libssl-dev

#### Clone andd build libscapi
- git clone https://github.com/cryptobiu/libscapi.git
- cd libscapi
- make

#### Build and Run tests
- cd ~/libscapi/test
- make
- ./tests.exe

### Docker Image

### Windows 7/8/10


