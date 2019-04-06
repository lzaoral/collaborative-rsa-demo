#include "common.hpp"

const Bignum RSA_Keys::e{ RSA_PUBLIC_KEY };

void RSA_Keys::generate_RSA_keys() {
	std::cout << "Generating keys... ";

	Rsa rsa{ e, RSA_MODULUS_BITS };

	const auto primes = rsa.getPrimes();
	const Bignum& p = primes.first;
	const Bignum& q = primes.second;

	const unsigned long bits = RSA_MODULUS_BITS / 4;
	check_num_bits(p, bits);
	check_num_bits(q, bits);

	Bignum p_phi = p - 1;
	Bignum q_phi = q - 1;

	e_coprimality_test(p_phi);
	e_coprimality_test(q_phi);

#ifdef VERBOSE
	std::cout << "Primes generated!\n\n";
#endif

	generate_private_key(p_phi, q_phi);
	generate_public_modulus(p, q);

	std::cout << "\x1B[1;32mOK\x1B[0m\n";
}

void RSA_Keys::check_num_bits(const Bignum& num, unsigned long bits) const {
	if (!num.check_num_bits(bits))
		throw std::out_of_range("Number generated is not a " + std::to_string(bits) + "-bit number.");
}

void RSA_Keys::e_coprimality_test(const Bignum& num) {
	Bignum gcdResult = Bignum::gcd(num, e);

	if (!gcdResult.is_one())
		throw std::runtime_error("The generated prime is not coprime with e.");

#ifdef VERBOSE
	std::cout << "Found a prime coprime with e: " << num << "\n\n";
#endif
}

void RSA_Keys::generate_public_modulus(const Bignum& p, const Bignum& q) {
	n = p * q;
	check_num_bits(n, RSA_MODULUS_BITS / 2);

#ifdef VERBOSE
	std::cout << "Public modulus: " << n << "\n\n";
#endif
}

void RSA_Keys::generate_private_key(const Bignum& phi_p, const Bignum& phi_q) {
	Bignum phi_n = phi_p * phi_q;
	Bignum d = Bignum::inverse(e, phi_n);

#ifdef VERBOSE
	std::cout << "Private key: " << d << "\n\n";
#endif

	if (is_test) {
		d_client = d;
		return;
	}

	d_client.set_random_value(RSA_MODULUS_BITS / 2);
	d_server = Bignum::mod_sub(d.get(), d_client, phi_n);

#ifdef VERBOSE
	std::cout << "Client share private key: " << d << "\n\n";
#endif
}

const Bignum& RSA_Keys::get_d_client() const {
	return d_client;
}

const Bignum& RSA_Keys::get_d_server() const {
	return d_server;
}

const Bignum& RSA_Keys::get_n() const {
	return n;
}

bool RSA_Keys::run_test() {
	is_test = true;

	Bignum original{ "48654681406840615136541141350146514654630436044654674266181" };

	for (std::size_t i = 1; i <= TEST_COUNT; i++) {
		std::cout << "TEST no. " << i << ": " << std::flush;

		generate_RSA_keys();

		Bignum ciphertext = Bignum::mod_exp(original, e, n);
		Bignum plaintext = Bignum::mod_exp(ciphertext, d_client, n);

		if (plaintext != original) {
			std::cerr << "\x1B[1;31mNOK\x1B[0m\n";
			return false;
		}

		std::cout << "\x1B[1;32mOK\x1B[0m\n";
	}

	is_test = false;
	return true;
}

bool regeneration() {
	std::string answer;

	while (true) {
		std::cout << "Do you want to regenerate client keys? (y/n): ";
		std::getline(std::cin, answer);

		if (std::cin.eof()) {
			std::cout << std::endl;
			return false;
		}

		if (std::cin.fail())
			throw std::runtime_error("STDIN error");

		if (answer == "n")
			return false;

		if (answer == "y")
			return true;

		std::cerr << "Unknown choice.\n";
	}
}