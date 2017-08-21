#Installing libscapi

### Ubuntu 16.04 LTS

#### Prerequisites
- sudo apt-get update
- sudo apt-get install git
- sudo apt-get install -y build-essential

#### Installing boost
- wget -O boost_1_64_0.tar.bz2 http://sourceforge.net/projects/boost/files/boost/1.64.0/boost_1_60_0.tar.bz2/download
- tar --bzip2 -xf boost_1_64_0.tar.bz2
-  ./bootstrap.sh
-  ./b2 -j8
- sudo ldconfig ~/boost_1_64_0/stage/lib/ ~/libscapi/install/lib/

#### Installing OpenSSL
- sudo apt-get install libssl-ocaml-dev libssl-dev

#### Clone and build libscapi
- git clone https://github.com/cryptobiu/libscapi.git
- cd libscapi
- make

#### Build and Run tests
- cd ~/libscapi/test
- make
- ./tests.exe
