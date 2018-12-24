#ifndef COMMON_HPP
#define COMMON_HPP
#pragma once

#include <iostream>
#include <string>
#include <vector>

#include "bignum_wrapper.hpp"

class RSA_Keys {
private:
	static const unsigned RSA_L_BITS{ 16 };
	static const unsigned RSA_S_BITS{ 200 };
	// static unsigned RSA_MODULUS_BITS{} // TODO: ???
	static const unsigned RSA_PUBLIC_KEY{ 853 };

	static const unsigned SECURITY_BITS{ 112 };

	static const unsigned S_PRIME_COUNT{ 5 };
	static const unsigned TEST_COUNT{ 1000 };

	const Bignum e;
	Bignum_CTX ctx;

public:
	RSA_Keys(unsigned publicKey = RSA_PUBLIC_KEY)
	    : e(publicKey) {}

	/**
    * Generates and stores keys required for encryption.
    */
	const std::pair<Bignum, Bignum> generateRSAKeys();

	/**
    * Runs self-test
    */
	bool runTest();

private:
	const std::pair<Bignum, Bignum> generateSafePrime();
	std::vector<Bignum> generateSPrimes() const;
	Bignum multiplySPrimes(const std::vector<Bignum> &SPrimes);
	Bignum &multiplyBy2a(Bignum &result);
	void primalityTestAndGeneration(Bignum &result, Bignum &resultPhi);

	const Bignum generatePublicModulus(const Bignum &p, const Bignum &q);
	const Bignum generatePrivateKey(const Bignum &phiP, const Bignum &phiQ);

	void handleError(int errCode) const;
};

#endif // COMMON_HPP
