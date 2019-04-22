#include "client_common.hpp"
#include "server_common.hpp"

#include <memory>

/**
 * @brief Prints the usage string.
 * 
 * @param argv0 relative path to the executable
 */
void printUsage(const std::string& argv0) {
	std::cerr << "Unknown parameters.\nUSAGE:\n"
	          << argv0 << "[client|server] [generate|sign|verify|test]\n"
	          << "\tgenerate - Generate and save the [client|server] keys\n"
	          << "\tsign - Sign the message\n"
	          << "\tverify - Verify the signature\n"
	          << "\ttest - Key generator self-test\n";
}

/**
 * @brief Prints out the header depending on the isServer
 * parameter.
 * 
 * @param isServer true if server false otherwise
 */
void printHeader(bool isServer) {
	std::cout << "\x1B[1;33m*** SMPC RSA "
	          << (isServer ? "SERVER" : "CLIENT")
	          << " DEMO ***\x1B[0m\n";
}

/**
 * @brief Parses the mode to used, client or server.
 * 
 * @param argv1 first positional argument
 * @return std::unique_ptr<SMPC_demo> returns pointer to the
 * selected mode, nullptr of unknown mode has been used.
 */
std::unique_ptr<SMPC_demo> parseMode(const std::string& argv1) {
	if (argv1 == "client") {
		printHeader(false);
		return std::make_unique<Client>();
	}

	if (argv1 == "server") {
		printHeader(true);
		return std::make_unique<Server>();
	}

	return nullptr;
}

/**
 * @brief Enum representing the allowed actions.
 */
enum class Action {
	GENERATE,
	SIGN,
	VERIFY,
	TEST,
	UNKNOWN
};

/**
 * @brief Parses the second positional argument
 * 
 * @param argv2 string with the first argument
 * @return Action value of the argument
 */
Action parseAction(const std::string& argv2) {
	if (argv2 == "generate") {
		return Action::GENERATE;
	}

	if (argv2 == "sign") {
		return Action::SIGN;
	}

	if (argv2 == "verify") {
		return Action::VERIFY;
	}

	if (argv2 == "test") {
		return Action::TEST;
	}

	return Action::UNKNOWN;
}

/**
 * @brief Main function of the client demo.
 */
int main(int argc, char* argv[]) {
	if (argc != 3) {
		printUsage(argv[0]);
		return EXIT_FAILURE;
	}

	std::unique_ptr<SMPC_demo> smpc_rsa = parseMode(argv[1]);
	if (!smpc_rsa) {
		printUsage(argv[0]);
		return EXIT_FAILURE;
	}

	std::cout << "\x1B[1;33m*** SMPC RSA CLIENT DEMO ***\x1B[0m\n";

	try {
		switch (parseAction(argv[2])) {
		case Action::GENERATE:
			smpc_rsa->generate_keys();
			break;

		case Action::SIGN:
			smpc_rsa->sign_message();
			break;

		case Action::VERIFY:
			smpc_rsa->verify_signature();
			break;

		case Action::TEST:
			RSA_keys_generator().run_test();
			break;

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
