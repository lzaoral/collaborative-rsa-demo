#include "common.hpp"

std::pair<Bignum, Bignum> getClientKeys() {
	std::cout << "Loading client keys...\n\n";
	std::ifstream in("client.key");

	if (!in)
		throw std::runtime_error("Client keys have not been generated!");

	// E is hardcoded and public

	Bignum d, n;

	in >> d >> n;

	std::cout << "Loading keys OK!\n\n";

	return { d, n };
}

Bignum multiplyNs(const Bignum& n1, const Bignum& n2) {
	Bignum n;
	Bignum_CTX ctx;

	if (!BN_mul(n.get(), n1.get(), n2.get(), ctx.get()))
		throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));

	return n;
}

void storeKeys(const std::pair<Bignum, Bignum>& client, const std::pair<Bignum, Bignum>& server) {
	std::cout << "Storing keys...\n\n";
	std::ofstream out("server.key");

	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	out << client.first << '\n'
	    << client.second << '\n'
	    << server.first << '\n'
	    << server.second << '\n'
	    << std::endl;

	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	std::cout << "Sending keys OK\n\n";
}

void sendKeys(const Bignum& e, const Bignum& n) {
	std::cout << "Sending keys...\n\n";
	std::ofstream out("public.key");

	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	out << e << n << std::endl;

	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	std::cout << "Sending keys OK\n\n";
}

void server(RSA_Keys& rsa) {
	const std::pair<Bignum, Bignum> client = getClientKeys();
	const std::pair<Bignum, Bignum> server = rsa.generateRSAKeys();
	const Bignum modulus = multiplyNs(client.first, server.first);

	storeKeys(client, server);
	sendKeys(rsa.e, modulus);
}

int main() {

	const std::string menuMsg("*** SERVER ***\n\n"
	                          "Choose action:\n"
	                          "1. Get client keys and generate server keys\n"
	                          "2. Test RSA implementation\n"
	                          "0. Exit program\n"
	                          "Selection:\n");

	RSA_Keys rsa{ false };

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
			if (!std::ifstream("client.key").good())
				std::cerr << "Client keys do not exist, generate then first!\n";

			if (!regeneration("server") || !regeneration("public"))
				break;

			std::cout << "*** PART TWO ***\n\nGenerating keys...\n\n";

			try {
				server(rsa);
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