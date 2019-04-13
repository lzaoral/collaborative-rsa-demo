#include "client_common.hpp"

/**
 * Prints the usage string.
 * 
 * @param argv0 relative path to the executable
 */
void printUsage(const std::string& argv0) {
	std::cerr << "Unknown parameters.\nUSAGE:\n"
	          << argv0 << " [generate|sign|verify|test]\n"
	          << "\tgenerate - Generate and save the client keys\n"
	          << "\tsign - Sign the message\n"
	          << "\tverify - Verify the signature\n"
	          << "\ttest - Key generator self-test\n";
}

/**
 * Enum representing the allowed actions of the client.
 */
enum class Action {
	GENERATE,
	SIGN,
	VERIFY,
	TEST,
	UNKNOWN
};

/**
 * Parses the first positional argument
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

	if (argv1 == "verify") {
		return Action::VERIFY;
	}

	if (argv1 == "test") {
		return Action::TEST;
	}

	return Action::UNKNOWN;
}

/**
 * Main function of the client demo.
 */
int main(int argc, char* argv[]) {
	if (argc != 2) {
		printUsage(argv[0]);
		return EXIT_FAILURE;
	}

	std::cout << "\x1B[1;33m*** SMPC RSA CLIENT DEMO ***\x1B[0m\n";

	try {
		switch (parseAction(argv[1])) {
		case Action::GENERATE: {
			if (std::ifstream(CLIENT_KEYS_CLIENT_FILE) && std::ifstream(CLIENT_KEYS_SERVER_FILE) && !regeneration())
				return EXIT_SUCCESS;

			RSA_keys_generator rsa;
			rsa.generate_RSA_keys();
			save_keys(rsa.get_d_client(), rsa.get_d_server(), rsa.get_n());
			break;
		}
		case Action::SIGN:
			sign_message();
			break;
		case Action::VERIFY:
			verify_signature();
			break;
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