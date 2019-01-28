#include "common.hpp"

#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <vector>

#include "rsa_wrapper.hpp"

void handleError(int errCode) {
	if (!errCode)
		throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
}

const std::string RSA_Keys::D_PRIME{ "4654156489464324346546846544532696" };
const Bignum RSA_Keys::e{ RSA_PUBLIC_KEY };

const std::pair<Bignum, Bignum> RSA_Keys::generateRSAKeys() {
	Bignum_CTX ctx;

	while (true) {
		try {

			const Primes primes = generatePrimes();

			if (verbose)
				std::cout << "Primes generated!\n\n";

			return { generatePrivateKey(primes.p.first, primes.q.first), generatePublicModulus(primes.p.second, primes.q.second) };

		} catch (const std::out_of_range& err) {
			std::cerr << err.what() << "\nRetrying...\n\n";
		}
	}
}

const RSA_Keys::Primes RSA_Keys::generatePrimes() {

	Rsa rsa{ e };

	auto primes = rsa.getPrimes();

	Bignum p{ primes.first };
	Bignum pPhi{ p };
	handleError(BN_sub_word(pPhi.get(), 0ul));
	coprimalityTest(p, pPhi);

	Bignum q{ primes.second };
	Bignum qPhi{ q };
	handleError(BN_sub_word(qPhi.get(), 0ul));
	coprimalityTest(q, qPhi);

	return { { pPhi, qPhi }, { p, q } };
}

void RSA_Keys::coprimalityTest(const Bignum& result, const Bignum& resultPhi) {
	Bignum gcdResult;

	if (BN_num_bits(result.get()) != RSA_MODULUS_BITS / 4)
		throw std::out_of_range("Prime is not a " + std::to_string(RSA_MODULUS_BITS / 4)
		    + "-bit number.\nNumber of bits: " + std::to_string(BN_num_bits(result.get())));

	handleError(BN_gcd(gcdResult.get(), resultPhi.get(), e.get(), ctx.get()));

	if (!BN_is_one(gcdResult.get()))
		throw std::runtime_error("The prime is not coprime with e");

	if (verbose)
		std::cout << "Found a prime coprime with e: " << result << "\n\n";
}

const Bignum RSA_Keys::generatePublicModulus(const Bignum& p, const Bignum& q) {
	Bignum n;
	handleError(BN_mul(n.get(), p.get(), q.get(), ctx.get()));

	if (BN_num_bits(n.get()) != RSA_MODULUS_BITS / 2)
		throw std::out_of_range("Modulus is not a " + std::to_string(RSA_MODULUS_BITS / 2) + "-bit number.");

	if (verbose)
		std::cout << "Public modulus: " << n << "\n\n";

	return n;
}

const Bignum RSA_Keys::generatePrivateKey(const Bignum& phiP, const Bignum& phiQ) {
	Bignum phiN;
	handleError(BN_mul(phiN.get(), phiP.get(), phiQ.get(), ctx.get()));

	Bignum d;
	handleError(BN_mod_inverse(d.get(), e.get(), phiN.get(), ctx.get()) != nullptr);

	if (verbose)
		std::cout << "Private key: " << d << "\n\n";

	if (!isTest) {
		Bignum dPrime{ D_PRIME };
		handleError(BN_mod_sub(d.get(), d.get(), dPrime.get(), phiN.get(), ctx.get()));

		if (verbose)
			std::cout << "Client share private key: " << d << "\n\n";
	}

	return d;
}

bool RSA_Keys::runTest() {
	verbose = false;
	isTest = true;

	Bignum original{ "48654681406840615136541141350146514654630436044654674266181" };

	for (std::size_t i = 1; i <= TEST_COUNT; i++) {
		std::cout << "TEST no. " << i << ": " << std::flush;

		const std::pair<Bignum, Bignum> keys = generateRSAKeys();

		Bignum ciphertext;
		handleError(BN_mod_exp(ciphertext.get(), original.get(), e.get(), keys.second.get(), ctx.get()));

		Bignum plaintext;
		handleError(BN_mod_exp(plaintext.get(), ciphertext.get(), keys.first.get(), keys.second.get(), ctx.get()));

		if (BN_cmp(plaintext.get(), original.get()) != 0) {
			std::cerr << "\x1B[1;31mOK\x1B[0m\n";
			return false;
		}

		std::cout << "\x1B[1;32mOK\x1B[0m\n";
	}

	verbose = true;
	isTest = false;
	return true;
}

bool regeneration(const std::string& file) {
	std::ifstream in(file + ".key");

	if (!in)
		return true;

	std::cout << "Do you want to regenerate " << file << ".key? (y/n)\n";
	std::string answer;

	while (true) {
		std::getline(std::cin, answer);

		if (answer == "y")
			return true;

		if (answer == "n") {
			std::cout << '\n';
			return false;
		}

		std::cout << "Unknown choice.\n";
	}
}