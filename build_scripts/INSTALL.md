# Installing libscapi

### Prerequisites

#### Ubuntu LTS
- sudo apt-get update
- sudo apt-get install -y git
- sudo apt-get install -y build-essential
- sudo apt-get install -y libssl-dev libgmp3-dev cmake liblog4cpp5-dev libboost-all-dev

#### CentOS 7.3
- sudo yum groupinstall -y 'Development Tools'
- sudo yum install -y update
- sudo yum install -y git
- sudo yum install -y openssl-devel libgmp3-dev cmake log4cpp-devel zlib1g-dev

#### Mac Osx
- /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
- brew update
- brew install openssl
- brew link openssl
- brew install nasm log4cpp

### Build libscapi
- from the user home directory, for example /home/ab/ (this is a limitation in the current version, will be fixed shortly)
- git clone https://github.com/cryptobiu/libscapi.git
- cd libscapi
- make
