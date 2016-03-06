#include "../../include/primitives/TrapdoorPermutationOpenSSL.hpp"


void OpenSSLRSAPermutation::setKey(PublicKey* publicKey, PrivateKey* privateKey) {
	RSAPublicKey * rsaPubKey = dynamic_cast<RSAPublicKey *>(publicKey);
	RSAPrivateKey * rsaPrivKey = dynamic_cast<RSAPrivateKey *>(privateKey);

	if (!rsaPubKey || (privateKey!=NULL && !rsaPrivKey))
		throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
	
	// Gets the values of modulus (N), pubExponent (e), privExponent (d).
	biginteger pubExponent = rsaPubKey->getPublicExponent();
	modulus = rsaPubKey->getModulus();

	if (privateKey) { // if privateKey is not NULL
		biginteger privExponent = rsaPrivKey->getPrivateExponent();
		RSAPrivateCrtKey* crtKey = dynamic_cast<RSAPrivateCrtKey*>(privateKey);

		if (crtKey) { // If private key is CRT private key.
			//gets all the crt parameters
			biginteger p = crtKey->getPrimeP();
			biginteger q = crtKey->getPrimeQ();
			biginteger dp = crtKey->getPrimeExponentP();
			biginteger dq = crtKey->getPrimeExponentQ();
			biginteger crt = crtKey->getCrtCoefficient();

			//Initializes the native object with crt key.
			rsa = initRSAPublicPrivateCrt(pubExponent, privExponent, p, q, dp, dq, crt);

		}
		else { //If private key is key with N, e, d.
			//Initialize the open SSL object with the RSA parameters - n, e, d.
			rsa = initRSAPublicPrivate(pubExponent, privExponent);
		}
	}
	else { // privateKey == NULL
		rsa = initRSAPublic(pubExponent);
	}
	// calls the parent's set key function that sets the keys.
	TrapdoorPermutationAbs::setKey(publicKey, privateKey);


}

RSA* OpenSSLRSAPermutation::initRSAPublicPrivateCrt(biginteger pubExp, biginteger privExp, biginteger p,
	biginteger q, biginteger dp, biginteger dq, biginteger crt) {

	RSA* rsa = RSA_new();
	rsa->n = biginteger_to_opensslbignum(modulus);
	rsa->e = biginteger_to_opensslbignum(pubExp);
	rsa->d = biginteger_to_opensslbignum(privExp);
	rsa->p = biginteger_to_opensslbignum(p);
	rsa->q = biginteger_to_opensslbignum(q);
	rsa->dmp1 = biginteger_to_opensslbignum(dp);
	rsa->dmq1 = biginteger_to_opensslbignum(dq);
	rsa->iqmp = biginteger_to_opensslbignum(crt);

	if ((rsa->n == NULL) || (rsa->e == NULL) || (rsa->d == NULL) || (rsa->p == NULL) ||
		(rsa->q == NULL) || (rsa->dmp1 == NULL) || (rsa->dmq1 == NULL) || (rsa->iqmp == NULL)) {
		RSA_free(rsa);
		return NULL;
	}
	return rsa;
}

RSA* OpenSSLRSAPermutation::initRSAPublicPrivate(biginteger pubExponent, biginteger privExponent) {
	RSA* rsa = RSA_new();
	rsa->n = biginteger_to_opensslbignum(modulus);
	rsa->e = biginteger_to_opensslbignum(pubExponent);
	rsa->d = biginteger_to_opensslbignum(privExponent);
	if ((rsa->n == NULL) || (rsa->e == NULL) || (rsa->d == NULL)) {
		RSA_free((RSA *)rsa);
		return NULL;
	}
	return rsa;
}

RSA* OpenSSLRSAPermutation::initRSAPublic(biginteger pubExponent) {
	RSA* rsa = RSA_new();

	rsa->n = biginteger_to_opensslbignum(modulus);
	rsa->e = biginteger_to_opensslbignum(pubExponent);
	if ((rsa->n == NULL) || (rsa->e == NULL)) {
		RSA_free(rsa);
		return NULL;
	}
	return rsa;
}

KeyPair OpenSSLRSAPermutation::generateKey(int keySize) {
	RSA* pair = RSA_new();
	BIGNUM* bne = BN_new();
	BN_set_word(bne, 65537);
	int ret = RSA_generate_key_ex(pair, keySize, bne, NULL);
	biginteger mod = opensslbignum_to_biginteger(pair->n);
	biginteger pubExp = opensslbignum_to_biginteger(pair->e);
	biginteger privExp = opensslbignum_to_biginteger(pair->d);
	KeyPair kp(new RSAPublicKey(mod, pubExp), new RSAPrivateKey(mod, privExp));
	RSA_free(pair);
	BN_free(bne);
	return kp;
}


TPElement* OpenSSLRSAPermutation::compute(TPElement * tpEl) {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");
	RSAElement * rsaEl = dynamic_cast<RSAElement *>(tpEl);
	if (!rsaEl) 
		throw invalid_argument("trapdoor element type doesn't match the trapdoor permutation type");

	// Get the pointer for the native object.
	biginteger elementP = rsaEl->getElement();

	//Call the native function.
	biginteger result = computeRSA(elementP);

	// Create and initialize a RSAElement with the result.
	RSAElement * returnEl = new RSAElement(modulus, result, false);

	return returnEl; // return the created TPElement.
}

biginteger OpenSSLRSAPermutation::computeRSA(biginteger elementP) {
	ERR_load_crypto_strings();
	//SSL_load_error_strings();
	// Seed the random geneartor.
#ifdef _WIN32
	RAND_screen(); // only defined for windows, reseeds from screen contents
#else
	RAND_poll(); // reseeds using hardware state (clock, interrupts, etc).
#endif

	// Allocate a new byte array to hold the output.
	int size = RSA_size(rsa);
	std::shared_ptr<byte> ret(new byte[size], std::default_delete<byte[]>());

	size_t encodedSize = bytesCount(elementP);
	std::shared_ptr<byte> encodedBi(new byte[encodedSize], std::default_delete<byte[]>());
	encodeBigInteger(elementP, encodedBi.get(), encodedSize);
	int success = RSA_public_encrypt(encodedSize, encodedBi.get(), ret.get(), rsa, RSA_NO_PADDING);
	if (-1 == success)
	{
		string error(ERR_reason_error_string(ERR_get_error()));
		throw runtime_error("failed to compute rsa " + error);
	}
	biginteger result = decodeBigInteger(ret.get(), size);
	return result;
}

TPElement* OpenSSLRSAPermutation::invert(TPElement * tpEl) {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");
	// If only the public key was set and not the private key - can't do the invert, throw exception.
	if (privKey == NULL && pubKey != NULL) 
		throw InvalidKeyException("in order to decrypt a message, this object must be initialized with private key");
	RSAElement * rsaEl = dynamic_cast<RSAElement *>(tpEl);
	if (!rsaEl)
		throw invalid_argument("trapdoor element type doesn't match the trapdoor permutation type");

	// gets the pointer for the native object.
	biginteger elementP = rsaEl->getElement();
	
	// Allocate a new byte array to hold the output.
	int size = RSA_size(rsa);
	std::shared_ptr<byte> ret(new byte[size], std::default_delete<byte[]>());

	size_t encodedSize = bytesCount(elementP);
	std::shared_ptr<byte> encodedBi(new byte[encodedSize], std::default_delete<byte[]>());
	encodeBigInteger(elementP, encodedBi.get(), encodedSize);
	
	string st(encodedBi.get(), encodedBi.get()+encodedSize);

	// invert the RSA permutation on the given bytes.
	int sucess = RSA_private_decrypt(encodedSize, encodedBi.get(), ret.get(), rsa, RSA_NO_PADDING);
	biginteger resValue = decodeBigInteger(ret.get(), size);
	// creates and initialize a RSAElement with the result.
	RSAElement * returnEl = new RSAElement(modulus, resValue, false);
	return returnEl; // return the result TPElement.
}
TPElValidity OpenSSLRSAPermutation::isElement(TPElement* tpEl) {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");
	RSAElement * rsaEl = dynamic_cast<RSAElement *>(tpEl);
	if (!rsaEl)
		throw invalid_argument("trapdoor element type doesn't match the trapdoor permutation type");

	TPElValidity validity;
	biginteger value = rsaEl->getElement();

	// If the modulus is unknown - returns DONT_KNOW. 
	if (modulus == NULL)
		validity = TPElValidity::DONT_KNOW;
	// If the value is valid (between 1 to (mod n) - 1) returns VALID.
	else if(value > 0 && value < modulus)
		validity = TPElValidity::VALID;
	// If the value is invalid returns NOT_VALID. 
	else
		validity = TPElValidity::NOT_VALID;

	// Returns the correct TPElValidity.
	return validity;
}

TPElement* OpenSSLRSAPermutation::generateRandomTPElement() {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");
	return new RSAElement(modulus);
}

OpenSSLRSAPermutation::~OpenSSLRSAPermutation() {
	RSA_free(rsa);
}