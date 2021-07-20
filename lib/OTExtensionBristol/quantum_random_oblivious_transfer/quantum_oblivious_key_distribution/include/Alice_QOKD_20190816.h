
# ifndef ALICE_QOKD_H_
# define ALICE_QOKD_H_

# include "netxpto_linux_20190816.h"

class AliceQOKD : public Block {

public:

	//##############################################################################################################

	AliceQOKD (std::initializer_list<Signal*> InputSig, std::initializer_list<Signal*> OutputSig) : Block(InputSig, OutputSig) {};
	
	bool runBlock(void);

private:

};

# endif


