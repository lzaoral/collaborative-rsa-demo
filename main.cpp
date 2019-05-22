#include "client_common.hpp"
#include "server_common.hpp"

#include <memory>

/**
 * Main file of the SMPC RSA Demo implementation.
 *
 * @author Lukáš Zaoral
 */

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
 * @brief Prints the usage string.
 * 
 * @param path relative path to the executable
 */
void print_usage(const std::string& path) {
	std::cerr << "Unknown parameters.\nUSAGE: " << path
	          << " [client|server] [generate|sign|verify|test]\n"
	          << "\tgenerate - Generate and save the [client|server] keys\n"
	          << "\tsign - Sign the message\n"
	          << "\tverify - Verify the signature\n"
	          << "\ttest - Single-party key generator self-test\n";
}

/**
 * @brief Prints out the header depending on the is_server
 * parameter.
 */
void print_header(bool is_server) {
	std::cout << "\x1B[1;33m*** SMPC RSA "
	          << (is_server ? "SERVER" : "CLIENT")
	          << " DEMO ***\x1B[0m\n";
}

/**
 * @brief Creates an instance of client or server
 * depending on the parameter.
 * 
 * @return std::unique_ptr<SMPC_demo> returns pointer to the
 * selected mode, nullptr of unknown mode has been used.
 */
std::unique_ptr<SMPC_demo> get_mode_instance(const std::string& mode) {
	if (mode == "client") {
		print_header(false);
		return std::make_unique<Client>();
	}

	if (mode == "server") {
		print_header(true);
		return std::make_unique<Server>();
	}

	return nullptr;
}

/**
 * @brief Parses the given string to corresponding Action
 * 
 * @return Action corresponding to the argument
 */
Action parse_action(const std::string& action) {
	if (action == "generate") {
		return Action::GENERATE;
	}

	if (action == "sign") {
		return Action::SIGN;
	}

	if (action == "verify") {
		return Action::VERIFY;
	}

	if (action == "test") {
		return Action::TEST;
	}

	return Action::UNKNOWN;
}

/**
 * @brief Main function of the client demo.
 */
int main(int argc, char* argv[]) {
	if (argc != 3) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	std::unique_ptr<SMPC_demo> smpc_rsa = get_mode_instance(argv[1]);
	if (!smpc_rsa) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	try {
		switch (parse_action(argv[2])) {
		case Action::GENERATE:
			smpc_rsa->generate_keys();
			break;

		case Action::SIGN:
			smpc_rsa->sign_message();
			break;

		case Action::VERIFY:
			smpc_rsa->verify_final_signature();
			break;

		case Action::TEST:
			RSA_keys_generator().run_test();
			break;

		default:
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	} catch (const std::exception& e) {
		std::cerr << "\x1B[1;31mNOK\x1B[0m\n"
		          << e.what() << '\n';
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
