#include "common.hpp"

void sendKeys(const Bignum& d, const Bignum& n) {
	std::cout << "Storing keys...\n\n";
	std::ofstream out("client.key");

	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	// E is hardcoded and public

	out << d << '\n'
	    << n << std::endl;

	std::cout << "Storing keys OK\n\n";
}

void updateClientKeys() {
	std::cout << "Updating keys...\n\n";
	std::ifstream cl("client.key");
	std::ifstream pub("public.key");

	if (!cl || !pub)
		throw std::runtime_error("Could not read the given keys.");

	std::string n1;
	std::string n;

	cl >> n1 >> n1;
	pub >> n >> n;

	cl.close();
	pub.close();

	std::ofstream out("client.key");
	if (!out)
		throw std::runtime_error("Could not write the given keys.");

	out << n1 << n;
	std::cout << "Client keys updated! OK\n\n";
}

void signMessage() {
	std::cout << "Signing...\n\n";

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
	Bignum dPrime{ D_PRIME };
	Bignum_CTX ctx;

	handleError(BN_mod_exp(signature.get(), message.get(), dPrime.get(), n1.get(), ctx.get()));

	std::ofstream out("client.sig");
	if (!out)
		throw std::runtime_error("Could not write the given keys.");

	out << message << signature;
	std::cout << "Signature computed! OK\n\n";
}

int main() {
	const std::string menuMsg("*** CLIENT ***\n\n"
	                          "Choose action:\n"
	                          "1. Generate and send client private keys\n"
	                          "2. Dispose of unneeded data\n"
	                          "3. Test RSA implementation\n"
	                          "4. Sign message and send to server\n"
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
			std::cout << "Exiting. ..\n";
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

			std::cout << "TESTS OK\n\n";

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

		default:
			std::cout << "Unknown choice\n\n";
		}
	}
}
