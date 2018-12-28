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

int main() {
	const std::string menuMsg("*** CLIENT ***\n\n"
	                          "Choose action:\n"
	                          "1. Generate and send client private keys\n"
	                          "2. Dispose of unneeded data\n"
	                          "3. Test RSA implementation\n"
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

		case 3: {
			if (!std::ifstream("client.key").good() || !std::ifstream("server.key").good()
			    || !std::ifstream("public.key").good()) {
				std::cerr << "Part 1, or part 2 of key generation process was skipped.\n";
				break;
			}

			// updateClientKeys();
		}

		default:
			std::cout << "Unknown choice\n\n";
		}
	}
}
