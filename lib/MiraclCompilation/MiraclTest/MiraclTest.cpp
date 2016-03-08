// MiraclTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../MiraclWin64/source/miracl/big.h"

int main()
{
	miracl *mip = mirsys(163, 2);
	Big b("32");
	cout << b.getbig()->len;
	cout << b.getbig()->w[0];
	bytes_to_big(3, "asaf", b.getbig());
	return 0;
}

