#include "common.hpp"

#include <fstream>

std::pair<Bignum, Bignum> get_client_keys() {
	std::cout << "Loading client keys... ";
	std::ifstream in("for_server.key");

	if (!in)
		throw std::runtime_error("Client keys have not been generated!");

	Bignum d_client, n1;
	in >> d_client >> n1;

	if (!in)
		throw std::runtime_error("Could not read the client keys!");

	std::cout << "\x1B[1;32mOK\x1B[0m\n";

	return { d_client, n1 };
}

Bignum multiply_and_check_moduli(const Bignum& n1, const Bignum& n2) {
	unsigned long bits = RSA_Keys::RSA_MODULUS_BITS / 2;
	check_num_bits(n1, bits);
	check_num_bits(n2, bits);

	Bignum n = n1 * n2;
	check_num_bits(n, RSA_Keys::RSA_MODULUS_BITS);

	return n;
}

void store_keys(const Bignum& d_client, const Bignum& n_client, const Bignum& d_server,
    const Bignum& n_server, const Bignum& n) {

	std::cout << "Storing keys... ";
	std::ofstream server("server.key"), public_key("public.key");

	if (!server || !public_key)
		throw std::runtime_error("Could not save the keys!");

	server << d_client << '\n'
	       << n_client << '\n'
	       << d_server << '\n'
	       << n_server;

	public_key << RSA_Keys::e << '\n'
	           << n;

	if (!server || !public_key)
		throw std::runtime_error("Could not save the keys!");

	std::cout << "\x1B[1;32mOK\x1B[0m\n";
}

void server(RSA_Keys& rsa) {
	const auto client = get_client_keys();
	rsa.generate_RSA_keys();

	store_keys(client.first, client.second, rsa.get_d_server(), rsa.get_n(), multiply_and_check_moduli(client.second, rsa.get_n()));
}

void sign_message() {
	std::cout << "Signing... ";

	std::ifstream server("server.key"), sign("client.sig");

	if (!server || !sign)
		throw std::runtime_error("Could read the given keys or client signature.");

	Bignum d_client, n_client, d_server, n_server;
	Bignum message, clientSig;

	server >> d_client >> n_client >> d_server >> n_server;
	sign >> message >> clientSig;

	if (!server || !sign)
		throw std::runtime_error("Could read the given keys or client signature.");

	unsigned long bits = RSA_Keys::RSA_MODULUS_BITS / 2;
	check_num_bits(n_client, bits);
	check_num_bits(n_server, bits);

	Bignum full_client_sig = Bignum::mod_exp(message, d_client, n_client);
	full_client_sig.mod_mul_self(clientSig, n_client);

	Bignum client_sig_check = Bignum::mod_exp(full_client_sig, RSA_Keys::e, n_client);
	if (message != client_sig_check)
		throw std::runtime_error("Fraudulent or corrupt client signature detected!");

	Bignum full_signature = Bignum::mod_exp(message, d_server, n_server) - full_client_sig;
	full_signature.mod_mul_self(Bignum::inverse(n_client, n_server), n_server);
	full_signature *= n_client;
	full_signature += full_client_sig;

	std::ofstream out("signature.sig");
	if (!out)
		throw std::runtime_error("Could not write out the final signature.");

	out << message << '\n'
	    << full_signature;

	if (!out)
		throw std::runtime_error("Could not write out the final signature.");

	std::cout << "\x1B[1;32mOK\x1B[0m\n\n";
}

int main() {
	const std::string menu_msg("\x1B[1;33m*** SMPC RSA SERVER DEMO ***\x1B[0m\n"
	                           "Choose action:\n"
	                           "1. Get client keys and generate server keys\n"
	                           "2. Finish computation of signature\n"
	                           "3. Test RSA implementation\n"
	                           "0. Exit program\n"
	                           "Selection:\n");

	RSA_Keys rsa{ true };

	while (true) {
		std::cout << menu_msg;

		unsigned input{};
		std::cin >> input;
		std::cin.ignore();

		switch (input) {
		case 0:
			return EXIT_SUCCESS;

		case 1: {
			// TODO:
			if (!std::ifstream("for_server.key")) {
				std::cerr << "Client keys do not exist, generate then first!\n";
				break;
			}

			if (std::ifstream("server.key") && std::ifstream("public.key") && !regeneration())
				break;

			try {
				server(rsa);
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}

		case 2: {
			// TODO:
			if (!std::ifstream("server.key") || !std::ifstream("client.sig")) {
				std::cerr << "Server keys have not been generated yet, or client side signature is missing!\n";
				break;
			}

			try {
				sign_message();
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}

		case 3:
			try {
				rsa.run_test();
				break;
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

		default:
			std::cout << "Unknown choice\n\n";
		}
	}
}