#include "server_common.hpp"

/**
 * @brief Prints the usage string.
 * 
 * @param argv0 relative path to the executable
 */
void printUsage(const std::string& argv0) {
	std::cerr << "Unknown parameters.\nUSAGE:\n"
	          << argv0 << " [generate|sign|verify|test]\n"
	          << "\tgenerate - Generate and save the client keys\n"
	          << "\tsign - Sign the message\n"
	          << "\ttest - Key generator self-test\n";
}

/**
 * @brief Enum representing the allowed actions of the client.
 */
enum class Action {
	GENERATE,
	SIGN,
	TEST,
	UNKNOWN
};

/**
 * @brief Parses the first positional argument
 * 
 * @param argv1 string with the first argument
 * @return Action value of the argument
 */
Action parseAction(const std::string& argv1) {
	if (argv1 == "generate") {
		return Action::GENERATE;
	}

	if (argv1 == "sign") {
		return Action::SIGN;
	}

	if (argv1 == "test") {
		return Action::TEST;
	}

	return Action::UNKNOWN;
}

/**
 * @brief Main function of the client demo.
 */
int main(int argc, char* argv[]) {
	if (argc != 2) {
		printUsage(argv[0]);
		return EXIT_FAILURE;
	}

	std::cout << "\x1B[1;33m*** SMPC RSA SERVER DEMO ***\x1B[0m\n";

	try {
		switch (parseAction(argv[1])) {
		case Action::GENERATE: {
			if (std::ifstream("server.key") && std::ifstream("public.key") && !regeneration())
				break;

			RSA_keys_generator rsa{ true }; // TODO: remove server mode???
			rsa.generate_RSA_keys();
			
			const auto client = get_client_keys();
			const auto n = multiply_and_check_moduli(client.second, rsa.get_n());

			store_keys(client.first, client.second, rsa.get_d2(), rsa.get_n(), n);
			break;
		}

		case 2: {
			try {
				sign_message();
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}

		case Action::TEST:
			RSA_keys_generator().run_test();
		default:
			printUsage(argv[0]);
			return EXIT_FAILURE;
		}
	} catch (const std::exception& e) {
		std::cerr << "\x1B[1;31mNOK\x1B[0m\n"
		          << e.what() << '\n';
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}