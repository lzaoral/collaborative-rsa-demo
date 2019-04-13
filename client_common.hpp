#ifndef CLIENT_COMMON_HPP
#define CLIENT_COMMON_HPP

#include "bignum_wrapper.hpp"
#include "common.hpp"
#include "rsa_wrapper.hpp"

#include <fstream>

/**
 * Saves generated keys to corresponding files, one for the client itself
 * and the other one for the server.
 * 
 * @param d_client - client share of the client private exponent (d'_1)
 * @param d_server - server share of the client private exponent (d''_1)
 * @param n - client modulus
 * @throws std::runtime_exception if an IO problem occurs
 * @throws std::out_of_range if an Bignum bit length test fails
 */
void save_keys(const Bignum& d_client, const Bignum& d_server, const Bignum& n) {
	std::cout << "Storing keys... ";

	check_num_bits(n, RSA_MODULUS_BITS);

	std::ofstream client(CLIENT_KEYS_CLIENT_FILE), server(CLIENT_KEYS_SERVER_FILE);
	if (!client || !server)
		throw std::runtime_error("Could not save the keys!");

	// exponent e is hardcoded and public, no need to send it out
	client << d_client << '\n'
	       << n;
	server << d_server << '\n'
	       << n;

	if (!client || !server)
		throw std::runtime_error("Could not save the keys!");

	std::cout << "\x1B[1;32mOK\x1B[0m\n";
}

/**
 * Signs the given message with client share of the client private exponent
 * and saves it to corresponting file.
 * 
 * @throws std::runtime_exception if an IO problem occurs or some Bignum
 *     operation failed
 * @throws std::out_of_range if an Bignum bit length test fails
 */
void sign_message() {
	std::cout << "Signing... ";

	std::ifstream client_keys(CLIENT_KEYS_CLIENT_FILE), messsage_file(MESSAGE_FILE);
	if (!client_keys || !messsage_file)
		throw std::runtime_error("Client keys have not been generated or message file is missing!");

	Bignum d_client, n, message;
	client_keys >> d_client >> n;
	messsage_file >> message;

	if (!client_keys || !messsage_file)
		throw std::runtime_error("Could not read the client keys or the message!");

	check_message_and_modulus(message, n);
	Bignum signature = Bignum::mod_exp(message, d_client, n);

	std::ofstream client_sig(CLIENT_SIG_SHARE_FILE);
	if (!client_sig)
		throw std::runtime_error("Could not save the signature!");

	client_sig << message << '\n'
	           << signature;

	if (!client_sig)
		throw std::runtime_error("Could not save the signature!");

	std::cout << "\x1B[1;32mOK\x1B[0m\n";
}

/**
 * Verifies the given signature.
 * 
 * @throws std::runtime_exception if an IO problem occurs or some Bignum
 *     operation failed
 * @throws std::out_of_range if an Bignum bit length test fails
 */
void verify_signature() {
	std::cout << "Verifying signature... ";

	std::ifstream signature_file(FINAL_SIG_FILE), public_key(PUBLIC_KEY_FILE);
	if (!signature_file || !public_key)
		throw std::runtime_error("Signature or public key files are missing. Did you run the server?");

	Bignum message, signature, n;
	signature_file >> message >> signature;
	// public exponent is hardcoded, we can skip it
	public_key >> n >> n;

	if (!signature_file || !public_key)
		throw std::runtime_error("Could not read signature or public keys.");

	check_message_and_modulus(message, n);
	std::cout << (Bignum::mod_exp(signature, RSA_PUBLIC_EXP, n) == message
	        ? "\x1B[1;31mNOK\x1B[0m\n"
	        : "\x1B[1;32mOK\x1B[0m\n");
}

#endif // CLIENT_COMMON_HPP
