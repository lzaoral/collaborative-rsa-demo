#ifndef COMMON_HPP
#define COMMON_HPP
#pragma once

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "bignum_wrapper.hpp"

class RSA_Keys {
private:
	static const unsigned SECURITY_BITS{ 112 };

	static const unsigned S_PRIME_COUNT{ 2 };
	static const unsigned TEST_COUNT{ 1000 };

	Bignum_CTX ctx;

public:
	static const unsigned RSA_L_BITS{ 16 };
	static const unsigned RSA_S_BITS{ 200 };
	static const unsigned RSA_MODULUS_BITS{ 2048 };
	static const unsigned RSA_PUBLIC_KEY{ 65537 };

	static const std::string D_PRIME;
	static const Bignum e;

	bool verbose{ false };
	const bool isClient;

	RSA_Keys(bool isClient)
	    : isClient(isClient) {}

	/**
    * Generates and stores keys required for encryption.
    */
	const std::pair<Bignum, Bignum> generateRSAKeys();

	/**
    * Runs self-test
    */
	bool runTest();

private:
	bool isTest{ false };

	const std::pair<Bignum, Bignum> generateSafePrime(bool longer);

	std::vector<Bignum> generateSPrimes() const;
	Bignum multiplySPrimes(const std::vector<Bignum> &SPrimes);
	void applyMask(Bignum &result, bool longer);
	Bignum &multiplyBy2a(Bignum &result, bool longer);
	void primalityTestAndGeneration(Bignum &result, Bignum &resultPhi, bool longer);

	const Bignum generatePublicModulus(const Bignum &p, const Bignum &q);
	const Bignum generatePrivateKey(const Bignum &phiP, const Bignum &phiQ);
};

/**
 * Handles error codes of OpenSSL functions.
 */
void handleError(int errCode);

/**
 * Checks whether the given keys have been already generated.
 */
bool regeneration(const std::string &file);

#endif // COMMON_HPP
