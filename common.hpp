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
	static const unsigned TEST_COUNT{ 1000 };

	Bignum_CTX ctx;

public:
	static const unsigned RSA_MODULUS_BITS{ 4096 };
	static const unsigned RSA_PUBLIC_KEY{ 65537 };

	static const std::string D_PRIME;
	static const Bignum e;

	bool verbose{ false };

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

	struct Primes {
		std::pair<Bignum, Bignum> p;
		std::pair<Bignum, Bignum> q;
	};

	const Primes generatePrimes();
	void coprimalityTest(const Bignum &result, const Bignum &resultPhi);

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
