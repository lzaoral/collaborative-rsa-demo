#include "common.hpp"
#include <fstream>

bool regeneration() {
	std::ifstream in("client.key");

	if (!in)
		return false;

	std::cout << "Do you want to regenerate client RSA keys? (y/n)\n";
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

void storeKeys(const Bignum& e, const Bignum& d, const Bignum& n) {
	std::cout << "Storing keys...\n\n";
	std::ofstream out("client.key");

	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	out << e << '\n'
	    << d << '\n'
	    << n << std::endl;

	std::cout << "Storing keys OK\n\n";
}

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
		std::cin.ignore();

		switch (input) {
		case 0: {
			std::cout << "Exiting. ..\n";
			return EXIT_SUCCESS;
		}
		case 1: {
			if (!regeneration())
				break;

			std::cout << "Generating keys...\n\n";

			try {
				const std::pair<Bignum, Bignum> pair = rsa.generateRSAKeys();
				storeKeys(rsa.e, pair.second, pair.first); // TODO: unintuitive
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
		default:
			std::cout << "Unknown choice\n\n";
		}
	}
}
