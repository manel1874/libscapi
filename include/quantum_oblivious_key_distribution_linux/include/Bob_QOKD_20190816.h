
# ifndef BOB_QOKD_H_
# define BOB_QOKD_H_

# include "netxpto_linux_20190816.h"

class BobQOKD : public Block {

public:

	//##############################################################################################################

	BobQOKD(std::initializer_list<Signal*> InputSig, std::initializer_list<Signal*> OutputSig) : Block(InputSig, OutputSig) {};

	bool runBlock(void);

private:

	//# State Variables #############################################################################################
	
	t_binary bobObliviousKeys[2];
	t_binary bobControlSignal[2];
};

# endif


