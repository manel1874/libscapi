#Installing libscapi

### Ubuntu 14.04LTS

#### Prerequisites
- sudo apt-get update
- sudo apt-get install git
- sudo apt-get install -y build-essential
- sudo apt-get install cmake
- sudo apt-get install libgmp3-dev

#### Installing boost
- wget -O boost_1_60_0.tar.bz2 http://sourceforge.net/projects/boost/files/boost/1.60.0/boost_1_60_0.tar.bz2/download
- tar --bzip2 -xf boost_1_60_0.tar.bz2
-  ./bootstrap.sh
-  ./b2 

#### Installing OpenSSL
- sudo apt-get install libssl-ocaml-dev libssl-dev

#### Clone andd build libscapi
- git clone https://github.com/cryptobiu/libscapi.git
- cd libscapi
- make
- sudo ldconfig ~/boost_1_60_0/stage/lib/ ~/libscapi/install/lib/

If the `make` step fails, try it with `sudo` i.e. `sudo make`

#### Build and Run tests
- cd ~/libscapi/test
- make
- ./tests.exe
