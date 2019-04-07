#ifndef CLIENT_COMMON_HPP
#define CLIENT_COMMON_HPP

#include "common.hpp"

#include <fstream>

void save_keys(const Bignum& d_client, const Bignum& d_server, const Bignum& n) {
	std::cout << "Storing keys... ";
	std::ofstream client("client_card.key"), server("for_server.key");

	if (!client || !server)
		throw std::runtime_error("Could not save the keys!");

	check_num_bits(n, RSA_Keys::RSA_MODULUS_BITS / 2);
	// E is hardcoded and public

	client << d_client << '\n'
	       << n;
	server << d_server << '\n'
	       << n;

	if (!client || !server)
		throw std::runtime_error("Could not save the keys!");

	std::cout << "\x1B[1;32mOK\x1B[0m\n";
}

#endif // CLIENT_COMMON_HPP