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

	handleError(BN_mul(n.get(), n1.get(), n2.get(), ctx.get()));
	handleError(BN_num_bits(n.get()) == 2048);

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

void signMessage(const Bignum& e) {
	std::cout << "Finishing signature...\n";

	std::ifstream server("server.key");
	std::ifstream sign("client.sig");

	if (!server || !sign)
		throw std::runtime_error("Could not write out the given keys.");

	Bignum d1, n1, d2, n2;
	Bignum message, clientSig;
	Bignum_CTX ctx;

	server >> d1 >> n1 >> d2 >> n2;
	sign >> message >> clientSig;

	Bignum fullClientSig;
	handleError(BN_mod_exp(fullClientSig.get(), message.get(), d1.get(), n1.get(), ctx.get()));
	handleError(BN_mul(fullClientSig.get(), fullClientSig.get(), clientSig.get(), ctx.get()));

	Bignum clientSigCheck;
	handleError(BN_mod_exp(clientSigCheck.get(), fullClientSig.get(), e.get(), n1.get(), ctx.get()));
	handleError(BN_cmp(clientSig.get(), clientSigCheck.get()) == 0);

	Bignum fullServerSig;
	handleError(BN_mod_exp(fullServerSig.get(), message.get(), d2.get(), n2.get(), ctx.get()));

	Bignum fullSignature;
	handleError(BN_sub(fullSignature.get(), fullServerSig.get(), fullClientSig.get()));

	Bignum fullClientSigInverse;
	handleError(BN_mod_inverse(fullClientSigInverse.get(), fullClientSig.get(), fullServerSig.get(), ctx.get()) != nullptr);

	handleError(BN_mod_mul(fullSignature.get(), fullClientSig.get(), fullClientSigInverse.get(), fullServerSig.get(), ctx.get()));
	handleError(BN_mul(fullSignature.get(), fullSignature.get(), fullClientSig.get(), ctx.get()));
	handleError(BN_add(fullSignature.get(), fullSignature.get(), fullClientSig.get()));

	std::ofstream out("signature.sig");
	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	out << fullSignature << message;
	std::cout << "Signature complete! OK\n\n";
}

int main() {

	const std::string menuMsg("*** SERVER ***\n\n"
	                          "Choose action:\n"
	                          "1. Get client keys and generate server keys\n"
	                          "2. Test RSA implementation\n"
	                          "3. Finish computation of signature\n"
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

		case 3: {
			if (!std::ifstream("client.key").good() || !std::ifstream("server.key").good()
			    || !std::ifstream("public.key").good() || !std::ifstream("client.sig")) {
				std::cerr << "Part 1, or part 2 of key generation process was skipped.\n";
				break;
			}

			try {
				signMessage(rsa.e);
			} catch (const std::exception& e) {
				std::cerr << e.what() << '\n';
				return EXIT_FAILURE;
			}

			break;
		}

		default:
			std::cout << "Unknown choice\n\n";
		}
	}
}