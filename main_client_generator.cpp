#include "client_common.hpp"
#include "common.hpp"

int main(int argc, char* argv[]) {
	if (argc > 2 || (argc == 2 && std::string(argv[1]) != "test")) {
		std::cerr << "Unknown parameters.\n"
		          << "USAGE: " << argv[0] << "[test]\n";

		return EXIT_FAILURE;
	}

	RSA_Keys rsa;
	std::cout << "\x1B[1;33m*** SMPC RSA CLIENT KEY GENERATOR ***\x1B[0m\n";

	if (argc == 2) {
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
	}

	if (std::ifstream("client_card.key") && std::ifstream("for_server.key") && !regeneration())
		return EXIT_FAILURE;

	try {
		rsa.generate_RSA_keys();
		save_keys(rsa.get_d_client(), rsa.get_d_server(), rsa.get_n());
	} catch (const std::exception& e) {
		std::cerr << e.what() << '\n';
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
