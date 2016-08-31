#include <iostream>
#include <ctime>
#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256
#include "pairing_3.h"

using namespace std;
int main(){
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	cout << "done!" << endl;
}

