#include <array>
#include <openssl/rand.h>
#include <vector>

#include <cstring> // TODO: ugly

#include "common.hpp"

const std::pair<Bignum, Bignum> RSA_Keys::generateRSAKeys() {
	Bignum_CTX ctx;

	std::cout << "Generating p...\n";
	const std::pair<Bignum, Bignum> p = generateSafePrime();

	std::cout << "Generating q...\n";
	const std::pair<Bignum, Bignum> q = generateSafePrime();

	std::cout << "(2^" << RSA_L_BITS << "-2^" << RSA_S_BITS << ")-safe primes generated!\n\n";

	return { generatePublicModulus(p.first, q.first), generatePrivateKey(p.second, q.second) };
}

const std::vector<Bignum> RSA_Keys::generateSPrimes() const {
	// TODO: random count of primes?
	/*
    if (!RAND_bytes(&count, 1)) {
        printf("Something went wrong! :(\n");
        getchar();


        return EXIT_FAILURE;
    }
    */

	std::vector<Bignum> primes;

	for (size_t i = 0; i < S_PRIME_COUNT; i++) {
		primes.emplace_back();
		unsigned char sbitCount{}; // TODO: use more bytes?

		do {
			handleError(!RAND_bytes(&sbitCount, 1));
		} while (sbitCount <= RSA_S_BITS);

		handleError(BN_generate_prime_ex(primes[i].get(), sbitCount, 0, nullptr, nullptr, nullptr));
	}

	return primes;
}

Bignum RSA_Keys::multiplySPrimes(const std::vector<Bignum>& SPrimes) {
	Bignum result{ 1 };

	for (const Bignum& prime : SPrimes)
		handleError(BN_mul(result.get(), prime.get(), result.get(), ctx.get()));
}

Bignum& RSA_Keys::multiplyBy2a(Bignum& result) {
	// MULTIPLY WITH RANDOM 1 <= a <= L a and 2 and then add 1

	std::array<unsigned char, RSA_L_BITS / 8> aBuffer;
	handleError(RAND_bytes(aBuffer.data(), RSA_L_BITS / 8));

	unsigned long a{}; // TODO: is ok?
	std::memcpy(&a, aBuffer.data(), RSA_L_BITS / 8);

	handleError(BN_mul_word(result.get(), a * 2));
}

const std::pair<Bignum, Bignum> RSA_Keys::generateSafePrime() {

	Bignum result = multiplySPrimes(generateSPrimes());
	Bignum resultPhi{ multiplyBy2a(result) };

	handleError(BN_add_word(result.get(), 1));

	primalityTestAndGeneration(result, resultPhi);
	return { result, resultPhi };
}

void RSA_Keys::primalityTestAndGeneration(Bignum& result, Bignum& resultPhi) {
	Bignum gcdResult;

	while (true) {
		switch (BN_is_prime_ex(result.get(), BN_prime_checks, ctx.get(), nullptr)) {
		case 1:
			handleError(BN_gcd(gcdResult.get(), resultPhi.get(), e.get(), ctx.get())); // TODO: GCD vulnerability in OpenSSL

			if (BN_is_one(gcdResult.get())) {
				std::cout << "Found a (2^" << RSA_L_BITS << "-2^" << RSA_S_BITS
				          << ")-prime coprime with e: " << result << "\n\n";

				return;
			}

			// no break, because we want to try other primes if no success

		case 0:
			handleError(BN_add_word(result.get(), 2));
			handleError(BN_add_word(resultPhi.get(), 2));
			break;

		default:
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
		}
	}
}

const Bignum RSA_Keys::generatePublicModulus(const Bignum& p, const Bignum& q) {
	Bignum n;
	handleError(BN_mul(n.get(), p.get(), q.get(), ctx.get()));

	std::cout << "Public modulus: " << n << "\n\n";
	return n;
}

const Bignum RSA_Keys::generatePrivateKey(const Bignum& phiP, const Bignum& phiQ) {
	Bignum phiN;
	handleError(!BN_mul(phiN.get(), phiP.get(), phiQ.get(), ctx.get()));

	Bignum d;
	handleError(BN_mod_inverse(d.get(), e.get(), phiN.get(), ctx.get()) == nullptr);

	std::cout << "Private key: " << d << "\n\n";
	return d;
}

bool RSA_Keys::runTest() {
	Bignum original{ "48654681406840615136541141350146514654630436044654674266181" };

	for (std::size_t i = 1; i <= TEST_COUNT; i++) {
		const std::pair<Bignum, Bignum> keys = generateRSAKeys();

		Bignum ciphertext;
		handleError(BN_mod_exp(ciphertext.get(), original.get(), e.get(), keys.first.get(), ctx.get()));

		Bignum plaintext;
		handleError(BN_mod_exp(plaintext.get(), ciphertext.get(), keys.second.get(), keys.first.get(), ctx.get()));

		if (BN_cmp(plaintext.get(), original.get()) != 0) {
			std::cerr << "\nTEST no" << i << ": NOK\n\n";
			return false;
		}

		std::cout << "\nTEST no" << i << ": OK\n\n";
	}

	return true;
}

void RSA_Keys::handleError(int errCode) const {
	if (!errCode)
		throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
}
