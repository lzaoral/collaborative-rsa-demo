#include "common.hpp"

void sendKeys(const Bignum& d, const Bignum& n) {
	std::cout << "Storing keys... ";
	std::ofstream out("client.key");

	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	// E is hardcoded and public

	out << d << '\n'
	    << n << std::endl;

	std::cout << "\x1B[1;32mOK\x1B[0m\n\n";
}

void updateClientKeys() {
	std::cout << "Updating keys... ";

	std::ifstream cl("client.key");
	std::ifstream pub("public.key");

	if (!cl || !pub)
		throw std::runtime_error("Could not read the given keys.");

	std::string n1;
	std::string n;

	cl >> n1 >> n1;
	pub >> n >> n;

	std::ofstream out("client.key");
	if (!out)
		throw std::runtime_error("Could not write the given keys.");

	out << n1 << '\n'
	    << n << std::endl;

	std::cout << "\x1B[1;32mOK\x1B[0m\n\n";
}

void signMessage() {
	std::cout << "Signing...\n";

	std::ifstream cl("client.key");
	if (!cl)
		throw std::runtime_error("Could not write the given keys.");

	Bignum n1;
	cl >> n1;

	Bignum message;

	while (true) {
		std::cout << "Message to be signed (use only decimal numbers):\n";

		try {
			std::cin >> message;
			break;

		} catch (const std::runtime_error& ex) {
			std::cerr << "Invalid message!\n";
			continue;
		}
	}

	// d' computed
	Bignum signature;
	Bignum dPrime{ RSA_Keys::D_PRIME };
	Bignum_CTX ctx;

	handleError(BN_mod_exp(signature.get(), message.get(), dPrime.get(), n1.get(), ctx.get()));

	std::ofstream out("client.sig");
	if (!out)
		throw std::runtime_error("Could not write the given keys.");

	out << message << '\n'
	    << signature;

	std::cout << "Signature computed! \x1B[1;32mOK\x1B[0m\n\n";
}

void verifySignature() {
	std::cout << "Verifying signature... ";

	std::ifstream sig("signature.sig");
	std::ifstream pub("public.key");
	if (!sig || !pub)
		throw std::runtime_error("Could not read signature.");

	Bignum signature, message;
	Bignum n;
	Bignum_CTX ctx;

	sig >> signature >> message;
	pub >> n >> n;

	Bignum tmp;
	handleError(BN_mod_exp(tmp.get(), signature.get(), RSA_Keys::e.get(), n.get(), ctx.get()));

	std::cout << (BN_cmp(message.get(), tmp.get()) ? "\x1B[1;31mNOK\x1B[0m\n\n" : "\x1B[1;32mOK\x1B[0m\n\n");
}

int main() {
	const std::string menuMsg("\x1B[1;33m*** CLIENT ***\x1B[0m\n\n"
	                          "Choose action:\n"
	                          "1. Generate and send client private keys\n"
	                          "2. Dispose of unneeded data\n"
	                          "3. Test RSA implementation\n"
	                          "4. Sign message and send to server\n"
	                          "5. Check signature\n"
	                          "0. Exit program\n"
	                          "Selection:\n");

	RSA_Keys rsa{ true };

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
			if (!regeneration("client"))
				break;

			std::cout << "*** PART ONE ***\n\nGenerating keys...\n\n";

			try {
				const std::pair<Bignum, Bignum> pair = rsa.generateRSAKeys();
				sendKeys(pair.first, pair.second);
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}

		case 2: {
			if (!std::ifstream("client.key").good() || !std::ifstream("server.key").good()
			    || !std::ifstream("public.key").good()) {
				std::cerr << "Part 1, or part 2 of key generation process was skipped.\n";
				break;
			}

			std::cout << "*** PART THREE ***\n\n";

			updateClientKeys();
			break;
		}

		case 3: {
			std::cout << "Running tests...\n\n";

			try {
				if (!rsa.runTest()) {
					std::cerr << "Tests failed!\n";

					return EXIT_FAILURE;
				}
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			std::cout << "\x1B[1;32mTESTS OK\x1B[0m\n\n";

			break;
		}

		case 4: {
			if (!std::ifstream("client.key").good() || !std::ifstream("server.key").good()
			    || !std::ifstream("public.key").good()) {
				std::cerr << "Part 1, or part 2 of key generation process was skipped.\n";
				break;
			}

			try {
				signMessage();
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}

		case 5: {
			if (!std::ifstream("signature.sig").good() || !std::ifstream("public.key").good()) {
				std::cerr << "File with message and signature does not exist.\n";
				break;
			}

			try {
				verifySignature();
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
