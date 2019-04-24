#ifndef CLIENT_COMMON_HPP
#define CLIENT_COMMON_HPP

#include "common.hpp"
#include <fstream>

class Client : public SMPC_demo {
public:
	/**
 	* @brief Generates and saves the client keys.
	*
 	* @throws std::runtime_exception if an IO problem occurs or some Bignum
 	* operation failed
 	* @throws std::out_of_range if an Bignum bit length test fails
 	*/
	void generate_keys() override {
		if (std::ifstream(CLIENT_KEYS_CLIENT_FILE) && std::ifstream(CLIENT_KEYS_SERVER_FILE)
		    && !regenerate_keys())
			return;

		RSA_keys_generator rsa;
		rsa.generate_RSA_keys();
		save_keys(rsa.get_d1_client(), rsa.get_d1_server(), rsa.get_n());
	}

	/**
 	* @brief Signs the given message with client share of the client
 	* private exponent and saves it to corresponding file.
 	* 
 	* @throws std::runtime_exception if an IO problem occurs or some Bignum
 	*     operation failed
 	* @throws std::out_of_range if an Bignum bit length test fails
 	*/
	void sign_message() override {
		std::cout << "Signing... ";

		// Load the keys
		std::ifstream client_keys(CLIENT_KEYS_CLIENT_FILE), messsage_file(MESSAGE_FILE);
		if (!client_keys || !messsage_file)
			throw std::runtime_error("Client key has not been generated or message file is missing!");

		Bignum d1_client, n, m;
		client_keys >> d1_client >> n;
		messsage_file >> m;

		if (!client_keys || !messsage_file)
			throw std::runtime_error("Could not read the client key or the message!");

		// Check and sign
		check_message_and_modulus(m, n, RSA_MODULUS_BITS);
		Bignum y = Bignum::mod_exp(m, d1_client, n);

		// Save the signature
		std::ofstream client_sig(CLIENT_SIG_SHARE_FILE);
		if (!client_sig)
			throw std::runtime_error("Could not save the signature!");

		client_sig << m << '\n'
		           << y << '\n';

		if (!client_sig)
			throw std::runtime_error("Could not save the signature!");

		std::cout << "\x1B[1;32mOK\x1B[0m\n";
	}

private:
	/**
 	* @brief Saves generated keys to corresponding files, one for the client
 	* itself and the other one for the server.
 	* 
 	* @param d1_client - client share of the client private exponent (d'_1)
 	* @param d1_server - server share of the client private exponent (d''_1)
 	* @param n1 - client modulus
 	* @throws std::runtime_exception if an IO problem occurs
 	* @throws std::out_of_range if the client modulus bit length test fails
 	*/
	void save_keys(const Bignum& d1_client, const Bignum& d1_server,
	    const Bignum& n1) {
		std::cout << "Storing keys... ";

		check_num_bits(n1, RSA_MODULUS_BITS);

		std::ofstream client(CLIENT_KEYS_CLIENT_FILE), server(CLIENT_KEYS_SERVER_FILE);
		if (!client || !server)
			throw std::runtime_error("Could not save the keys!");

		// exponent e is hardcoded and public, no need to send it out
		client << d1_client << '\n'
		       << n1 << '\n';
		server << d1_server << '\n'
		       << n1 << '\n';

		if (!client || !server)
			throw std::runtime_error("Could not save the keys!");

		std::cout << "\x1B[1;32mOK\x1B[0m\n";
	}
};

#endif // CLIENT_COMMON_HPP
