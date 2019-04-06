#include "common.hpp"

#include <fstream>

void save_keys(const Bignum& d_client, const Bignum& d_server, const Bignum& n) {
	std::cout << "Storing keys... ";
	std::ofstream client("client_card.key"), server("for_server.key");

	if (!client || !server)
		throw std::runtime_error("Could not save keys.");

	// E is hardcoded and public

	client << d_client << '\n'
	       << n << std::endl;

	server << d_server << '\n'
	       << n << std::endl;

	std::cout << "\x1B[1;32mOK\x1B[0m\n";
}

int main() {
	RSA_Keys rsa;
	std::cout << "\x1B[1;33m*** SMPC RSA CLIENT KEY GENERATOR ***\x1B[0m\n";

	if (std::ifstream("client_card.key").good() && std::ifstream("for_server.key").good() && !regeneration())
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
