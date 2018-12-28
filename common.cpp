#include <openssl/rand.h>

#include <cstring> // TODO: ugly

#include "common.hpp"

const std::pair<Bignum, Bignum> RSA_Keys::generateRSAKeys() {
	Bignum_CTX ctx;
	while (true) {
		try {
			if (verbose)
				std::cout << "Generating p...\n";

			const std::pair<Bignum, Bignum> p = generateSafePrime(false);

			if (verbose)
				std::cout << "Generating q...\n";

			const std::pair<Bignum, Bignum> q = generateSafePrime(true);

			if (verbose)
				std::cout << "(2^" << RSA_L_BITS << "-2^" << RSA_S_BITS << ")-safe primes generated!\n\n";

			return { generatePrivateKey(p.second, q.second), generatePublicModulus(p.first, q.first) };

		} catch (const std::out_of_range& err) {
			std::cerr << err.what() << "\nRetrying...\n\n";
		}
	}
}

std::vector<Bignum> RSA_Keys::generateSPrimes() const {
	// handleError(RAND_bytes(&count, 1)); TODO: random count of s-primes?

	std::vector<Bignum> primes;

	for (size_t i = 0; i < S_PRIME_COUNT; i++) {
		primes.emplace_back();
		unsigned char sbitCount{}; // TODO: use more bytes?

		do {
			handleError(RAND_bytes(&sbitCount, 1));
		} while (sbitCount <= RSA_S_BITS || 245 < sbitCount);

		handleError(BN_generate_prime_ex(primes[i].get(), sbitCount, 0, nullptr, nullptr, nullptr));
	}

	return primes;
}

Bignum RSA_Keys::multiplySPrimes(const std::vector<Bignum>& SPrimes) {
	Bignum result{ 1 };

	for (const Bignum& prime : SPrimes)
		handleError(BN_mul(result.get(), prime.get(), result.get(), ctx.get()));

	return result;
}

void RSA_Keys::applyMask(Bignum& result, bool longer) { // not the best solution
	handleError(BN_set_bit(result.get(), RSA_MODULUS_BITS / 4 - (longer ? 0 : 1)));

	if (BN_num_bits(result.get()) > 512 + (longer ? 1 : 0))
		handleError(BN_mask_bits(result.get(), RSA_MODULUS_BITS / 4));
}

Bignum& RSA_Keys::multiplyBy2a(Bignum& result, bool longer) {
	const int bytesCount = RSA_L_BITS / 8;

	std::vector<unsigned char> aBuffer(bytesCount);
	handleError(RAND_bytes(aBuffer.data(), bytesCount));

	unsigned long a{}; // TODO: is ok?
	std::memcpy(&a, aBuffer.data(), bytesCount);

	handleError(BN_mul_word(result.get(), a * 2));

	applyMask(result, longer);
	return result;
}

const std::pair<Bignum, Bignum> RSA_Keys::generateSafePrime(bool longer) {

	Bignum result = multiplySPrimes(generateSPrimes());
	Bignum resultPhi{ multiplyBy2a(result, longer) };

	handleError(BN_add_word(result.get(), 1));

	primalityTestAndGeneration(result, resultPhi, longer);
	return { result, resultPhi };
}

void RSA_Keys::primalityTestAndGeneration(Bignum& result, Bignum& resultPhi, bool longer) {
	Bignum gcdResult;

	while (true) {
		if (BN_num_bits(result.get()) != RSA_MODULUS_BITS / 4 + (longer ? 1 : 0))
			throw std::out_of_range("Prime is not a 512-bit number.");

		switch (BN_is_prime_ex(result.get(), BN_prime_checks, ctx.get(), nullptr)) {
		case 1:
			handleError(BN_gcd(gcdResult.get(), resultPhi.get(), e.get(), ctx.get())); // TODO: GCD vulnerability in OpenSSL

			if (BN_is_one(gcdResult.get())) {
				if (verbose)
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

	if (BN_num_bits(n.get()) != RSA_MODULUS_BITS / 2)
		throw std::out_of_range("Modulus is not a 1024-bit number.");

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

	if (!isTest && isClient) {
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
			std::cerr << "NOK\n";
			return false;
		}

		std::cout << "OK\n";
	}

	verbose = true;
	isTest = false;
	return true;
}

void RSA_Keys::handleError(int errCode) const {
	if (!errCode)
		throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
}

bool regeneration(const std::string& file) {
	std::ifstream in(file + ".key");

	if (!in)
		return false;

	std::cout << "Do you want to regenerate " << file << ".key? (y/n)\n";
	std::string answer;

	while (true) {
		std::getline(std::cin, answer);

		if (answer == "y")
			return true;

		if (answer == "n")
			return false;

		std::cout << "Unknown choice.\n";
	}
}