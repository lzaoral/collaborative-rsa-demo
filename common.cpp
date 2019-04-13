#include "common.hpp"

void RSA_keys_generator::generate_RSA_keys() {
	if (!is_test)
		std::cout << "Generating keys... ";

	const auto primes = Rsa(RSA_PUBLIC_EXP, RSA_MODULUS_BITS * 2, RSA_PRIME_COUNT).getPrimes();
	const Bignum& p = primes.first;
	const Bignum& q = primes.second;

	const auto bits = RSA_MODULUS_BITS / 2;
	check_num_bits(p, bits);
	check_num_bits(q, bits);

	Bignum p_phi = p - 1;
	Bignum q_phi = q - 1;

	e_coprimality_test(p_phi);
	e_coprimality_test(q_phi);

	generate_private_key(p_phi, q_phi);
	generate_modulus(p, q);

	if (!is_test)
		std::cout << "\x1B[1;32mOK\x1B[0m\n";
}

void RSA_keys_generator::e_coprimality_test(const Bignum& num) {
	Bignum gcdResult = Bignum::gcd(num, RSA_PUBLIC_EXP);

	if (!gcdResult.is_one())
		throw std::runtime_error("The generated prime is not coprime with e.");
}

void RSA_keys_generator::generate_modulus(const Bignum& p, const Bignum& q) {
	n = p * q;
	check_num_bits(n, RSA_MODULUS_BITS);
}

void RSA_keys_generator::generate_private_key(const Bignum& phi_p, const Bignum& phi_q) {
	Bignum phi_n = phi_p * phi_q;
	Bignum d = Bignum::inverse(RSA_PUBLIC_EXP, phi_n);

	if (is_test || is_server) {
		d_server = d;
		return;
	}

	d_client.set_random_value(RSA_MODULUS_BITS);
	d_client.mod(phi_n);

	d_server = Bignum::mod_sub(d.get(), d_client, phi_n);
}

const Bignum& RSA_keys_generator::get_d_client() const {
	return d_client;
}

const Bignum& RSA_keys_generator::get_d_server() const {
	return d_server;
}

const Bignum& RSA_keys_generator::get_n() const {
	return n;
}

void RSA_keys_generator::run_test() {
	is_test = true;
	std::cout << "Testing...\n";
	bool failed{ false };

	Bignum original{ "48654681406840615136541141350146514654630436044654674266181" };

	for (std::size_t i = 1; i <= TEST_COUNT; i++) {
		std::cout << "TEST " << i << ": " << std::flush;
		generate_RSA_keys();

		Bignum ciphertext = Bignum::mod_exp(original, RSA_PUBLIC_EXP, n);
		Bignum plaintext = Bignum::mod_exp(ciphertext, d_server, n);

		if (plaintext != original) {
			failed = true;
			std::cerr << "\x1B[1;31mNOK\x1B[0m\n";
			continue;
		}

		std::cout << "\x1B[1;32mOK\x1B[0m\n";
	}

	std::cout << "Result: " << (failed ? "\x1B[1;31mNOK\x1B[0m\n" : "\x1B[1;32mOK\x1B[0m\n");
	is_test = false;
}

void check_num_bits(const Bignum& num, unsigned long bits) {
	if (!num.check_num_bits(bits))
		throw std::out_of_range("Number generated is not a " + std::to_string(bits) + "-bit number.");
}

void check_message_and_modulus(const Bignum& message, const Bignum& n) {
	check_num_bits(n, RSA_MODULUS_BITS);
	if (message > n)
		throw std::out_of_range("Message cannot be greater than the modulus");
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