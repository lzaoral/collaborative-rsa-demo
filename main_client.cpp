#include "client_common.hpp"
#include "common.hpp"

#include <fstream>

void sign_message() {
	std::cout << "Signing... ";

	std::ifstream client("client_card.key");
	if (!client)
		throw std::runtime_error("Client keys have not been generated!");

	Bignum d_client, n;
	client >> d_client >> n;

	if (!client)
		throw std::runtime_error("Could not read the client keys!");

	Bignum message;

	// refactor message from file
	// TODO: HERE

	// d' computed
	Bignum signature = Bignum::mod_exp(message, d_client, n);

	std::ofstream out("client.sig");
	if (!out)
		throw std::runtime_error("Could not save the signature!");

	out << message << '\n'
	    << signature;

	if (!out)
		throw std::runtime_error("Could not save the signature!");

	std::cout << "\x1B[1;32mOK\x1B[0m\n";
}

void verify_signature() {
	std::cout << "Verifying signature... ";

	std::ifstream signature_file("signature.sig"), public_key("public.key");
	if (!signature_file || !public_key)
		throw std::runtime_error("Could not read signature or public keys.");

	Bignum msg, sig, n;
	signature_file >> msg >> sig;
	
	// TODO: WTF?
	public_key >> n >> n;

	if (!signature_file || !public_key)
		throw std::runtime_error("Could not read signature or public keys.");

	std::cout << (Bignum::mod_exp(sig, RSA_Keys::e, n) == msg ? "\x1B[1;31mNOK\x1B[0m\n\n" : "\x1B[1;32mOK\x1B[0m\n\n");
}

int main() {
	const std::string menuMsg("\x1B[1;33m*** SMPC RSA CLIENT DEMO ***\x1B[0m\n\n"
	                          "Choose action:\n"
	                          "1. Generate and send client private keys\n"
	                          "2. Sign message and send to server\n"
	                          "3. Check signature (custom)\n"
	                          "4. Test RSA implementation\n"
	                          "0. Exit program\n"
	                          "Selection:\n");

	RSA_Keys rsa;

	while (true) {
		std::cout << menuMsg;

		unsigned input{};
		std::cin >> input;
		std::cin.ignore();

		switch (input) {
		case 0: {
			std::cout << "Exiting...\n";
			return EXIT_SUCCESS;
		}

		case 1: {
			// TODO:
			if (std::ifstream("client_card.key") && std::ifstream("for_server.key") && !regeneration())
				break;

			try {
				rsa.generate_RSA_keys();
				save_keys(rsa.get_d_client(), rsa.get_d_server(), rsa.get_n());
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}

		case 2: {
			// TODO:
			if (!std::ifstream("client_card.key").good())
				break;

			try {
				sign_message();
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}

		case 3: {
			// TODO:
			if (!std::ifstream("signature.sig").good() || !std::ifstream("public.key").good()) {
				std::cerr << "File with message or signature does not exist.\n";
				break;
			}

			try {
				verify_signature();
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}

		case 4: {
			try {
				std::cout << "Testing...\n";
				bool ret = rsa.run_test();

				std::cout << "Result: " << (ret ? "\x1B[1;32mOK\x1B[0m\n" : "\x1B[1;31mNOK\x1B[0m\n")
						<< std::endl;

				return ret;
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

				break;
			}

		default:
			std::cout << "Unknown choice.\n\n";
		}
	}
}
