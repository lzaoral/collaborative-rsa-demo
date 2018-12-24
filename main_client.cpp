#include "common.hpp"

int main() {

	const std::string menuMsg("Choose action:\n"
	                          "1. Generate and store keys\n"
	                          "2. Test implementation\n"
	                          "0. Exit program\n"
	                          "Selection:\n");

	RSA_Keys rsa;

	while (true) {
		std::cout << menuMsg;

		unsigned input{};
		std::cin >> input;

		switch (input) {

		case 0: {
			std::cout << "Exiting. ..\n";
			return EXIT_SUCCESS;
		}
		case 1: {
			std::cout << "Generating keys...\n\n";

			// CHECK THAT KEYS HAVE BEEN GENERATED

			try {
				const auto pair = rsa.generateRSAKeys();
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}
		case 2: {
			std::cout << "Running tests...\n\n";

			if (!rsa.runTest()) {
				std::cerr << "Tests failed!\n";

				return EXIT_FAILURE;
			}

			std::cout << "TESTS OK\n\n";

			break;
		}
		default:
			std::cout << "Unknown choice\n\n";
		}
	}
}
