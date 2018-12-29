#include "common.hpp"

std::pair<Bignum, Bignum> getClientKeys() {
	std::cout << "Loading client keys... ";
	std::ifstream in("client.key");

	if (!in)
		throw std::runtime_error("Client keys have not been generated!");

	Bignum d, n;
	in >> d >> n;

	std::cout << "\x1B[1;32mOK\x1B[0m\n";

	return { d, n };
}

Bignum multiplyNs(const Bignum& n1, const Bignum& n2) {
	Bignum n;
	Bignum_CTX ctx;

	handleError(BN_num_bits(n1.get()) == 1024);
	handleError(BN_num_bits(n2.get()) == 1025);

	handleError(BN_mul(n.get(), n1.get(), n2.get(), ctx.get()));
	handleError(BN_num_bits(n.get()) == 2048);

	return n;
}

void storeKeys(const std::pair<Bignum, Bignum>& client, const std::pair<Bignum, Bignum>& server) {
	std::cout << "Storing keys... ";
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

	std::cout << "\x1B[1;32mOK\x1B[0m\n";
}

void sendKeys(const Bignum& n) {
	std::cout << "Sending keys... ";
	std::ofstream out("public.key");

	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	out << RSA_Keys::e << '\n'
	    << n << std::endl;

	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	std::cout << "\x1B[1;32mOK\x1B[0m\n\n";
}

void server(RSA_Keys& rsa) {
	const std::pair<Bignum, Bignum> client = getClientKeys();
	const std::pair<Bignum, Bignum> server = rsa.generateRSAKeys();
	const Bignum modulus = multiplyNs(client.second, server.second);

	storeKeys(client, server);
	sendKeys(modulus);
}

void signMessage() {
	std::cout << "Finishing signature... ";

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
	handleError(BN_mod_mul(fullClientSig.get(), fullClientSig.get(), clientSig.get(), n1.get(), ctx.get()));

	Bignum clientSigCheck;
	handleError(BN_mod_exp(clientSigCheck.get(), fullClientSig.get(), RSA_Keys::e.get(), n1.get(), ctx.get()));
	handleError(BN_cmp(message.get(), clientSigCheck.get()) == 0);

	Bignum fullServerSig;
	handleError(BN_mod_exp(fullServerSig.get(), message.get(), d2.get(), n2.get(), ctx.get()));

	Bignum fullSignature;
	handleError(BN_sub(fullSignature.get(), fullServerSig.get(), fullClientSig.get()));

	Bignum n1Inverse;
	handleError(BN_mod_inverse(n1Inverse.get(), n1.get(), n2.get(), ctx.get()) != nullptr);

	handleError(BN_mod_mul(fullSignature.get(), fullSignature.get(), n1Inverse.get(), n2.get(), ctx.get()));
	handleError(BN_mul(fullSignature.get(), fullSignature.get(), n1.get(), ctx.get()));
	handleError(BN_add(fullSignature.get(), fullSignature.get(), fullClientSig.get()));

	std::ofstream out("signature.sig");
	if (!out)
		throw std::runtime_error("Could not write out the given keys.");

	out << fullSignature << '\n'
	    << message << std::endl;

	std::cout << "\x1B[1;32mOK\x1B[0m\n\n";
}

int main() {

	const std::string menuMsg("\x1B[1;33m*** SERVER ***\x1B[0m\n\n"
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
			if (!std::ifstream("client.key").good()) {
				std::cerr << "Client keys do not exist, generate then first!\n";
				break;
			}

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

			std::cout << "\x1B[1;32mTESTS OK\x1B[0m\n\n";

			break;
		}

		case 3: {
			if (!std::ifstream("client.key").good() || !std::ifstream("server.key").good()
			    || !std::ifstream("public.key").good() || !std::ifstream("client.sig")) {
				std::cerr << "Part 1, or part 2 of key generation process was skipped.\n";
				break;
			}

			try {
				signMessage();
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