#include "../../include/infra/MathAlgorithms.hpp"

biginteger MathAlgorithms::modInverse(biginteger a, biginteger m)
{
	biginteger b0 = m, t, q;
	biginteger x0 = 0, x1 = 1;
	if (m == 1) return 1;
	while (a > 1) {
		q = a / m;
		t = m, m = a % m, a = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < 0) x1 += b0;
	return x1;
}

biginteger MathAlgorithms::chineseRemainderTheorem(const vector<biginteger> & congruences, const vector<biginteger> & moduli)
{
	biginteger retval = 0;
	biginteger all = 1;
	for (int i = 0; i < moduli.size(); i++)
		all *= moduli[i];
	for (int i = 0; i < moduli.size(); i++)
	{
		biginteger a = moduli[i];
		biginteger b = all / a; 
		biginteger b_ = modInverse(b, a);
		biginteger tmp = b*b_; 
		tmp *= congruences[i]; 
		retval += tmp; 	
	}
	return retval % all; 
}

int MathAlgorithms::factorial(int n) {
	int fact = 1; // this  will be the result 
	for (int i = 1; i <= n; i++)
		fact *= i;
	return fact;
}


biginteger MathAlgorithms::factorialBI(int n) {
	biginteger fact = 1 ; // this  will be the result 
	for (int i = 1; i <= n; i++)
		fact *= i;
	return fact;
}

MathAlgorithms::SquareRootResults MathAlgorithms::sqrtModP_3_4(biginteger z, biginteger p) {
	//We assume here (and we do not check for efficiency reasons) that p is a prime
	//We do check that the prime p = 3 mod 4, if not throw exception 
	if (p%4 != 3)
		throw invalid_argument("p has to be a prime such that p = 3 mod 4");

	biginteger exponent = (p + 1) / 4;
	biginteger x = mp::powm(z, exponent, p);  // z.modPow(exponent, p);
	return SquareRootResults(x, (-x + p) % p); // we want to avoid negative modolus
}

/*-------------------------------------------------------------*/
//}