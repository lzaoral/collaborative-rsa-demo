#ifndef SERVER_COMMON_HPP
#define SERVER_COMMON_HPP

#include "common.hpp"
#include <fstream>

class Server : public SMPC_demo {
public:
	/**
 	* @brief Generates and saves the server keys.
	*
 	* @throws std::runtime_exception if an IO problem occurs or some Bignum
 	* operation failed
 	* @throws std::out_of_range if an Bignum bit length test fails
 	*/
	void generate_keys() override {
		if (std::ifstream(SERVER_KEYS_FILE) && std::ifstream(PUBLIC_KEY_FILE)
		    && !regenerate_keys())
			return;

		const auto client = get_client_keys();
		
		RSA_keys_generator rsa{ true };
		rsa.generate_RSA_keys();

		const auto n = multiply_and_check_moduli(client.second, rsa.get_n());

		save_keys(client.first, client.second, rsa.get_d2(), rsa.get_n(), n);
	}

	/**
 	* @brief Finishes and checks authenticity of the client signature.
    * After that computes and saves the final signature.
 	* 
 	* @throws std::runtime_exception if an IO problem occurs or some Bignum
 	*     operation failed
 	* @throws std::out_of_range if an Bignum bit length test fails
 	*/
	void sign_message() override {
		std::cout << "Signing... ";

		// Load the keys and partial signature
		std::ifstream server(SERVER_KEYS_FILE), sign(CLIENT_SIG_SHARE_FILE);
		if (!server || !sign)
			throw std::runtime_error("Could read the given keys or client signature.");

		Bignum d1_server, n1, d2, n2, m, y;
		server >> d1_server >> n1 >> d2 >> n2;
		sign >> m >> y;

		if (!server || !sign)
			throw std::runtime_error("Could read the given keys or client signature.");

		// Check valid input
		check_message_and_modulus(m, n1, RSA_MODULUS_BITS);
		check_message_and_modulus(m, n2, RSA_MODULUS_BITS);
		check_num_bits(n1 * n2, RSA_MODULUS_BITS * 2);

		// Finish and check the client signature
		Bignum s1 = Bignum::mod_exp(m, d1_server, n1);
		s1.mod_mul_self(y, n1);

		Bignum m_test = Bignum::mod_exp(s1, RSA_PUBLIC_EXP, n1);
		if (m != m_test)
			throw std::runtime_error("Fraudulent or corrupt client signature detected!");

		// Compute the full signature
		// s = (((s2 - s1) / n1) mod n2) * n1 + s1
		Bignum s = Bignum::mod_exp(m, d2, n2) - s1;
		s.mod_mul_self(Bignum::inverse(n1, n2), n2);
		s *= n1;
		s += s1;

		// Save the signature
		std::ofstream out(FINAL_SIG_FILE);
		if (!out)
			throw std::runtime_error("Could not write out the final signature.");

		out << m << '\n'
		    << s << '\n';

		if (!out)
			throw std::runtime_error("Could not write out the final signature.");

		std::cout << "\x1B[1;32mOK\x1B[0m\n";
	}

private:
	/**
    * @brief Reads and returns the server share of client keys.
    * 
    * @return pair containing the server share of the client key
    *     and client modulus in this order
    * @throws std::runtime_exception if an IO problem occurs
    * @throws std::out_of_range if the client modulus bit length test fails
    */
	static std::pair<Bignum, Bignum> get_client_keys() {
		std::cout << "Loading client keys... ";

		std::ifstream in(CLIENT_KEYS_SERVER_FILE);
		if (!in)
			throw std::runtime_error("Client keys have not been generated!");

		Bignum d1_server, n1;
		in >> d1_server >> n1;

		if (!in)
			throw std::runtime_error("Could not read the client keys!");

		std::cout << "\x1B[1;32mOK\x1B[0m\n";
		return { d1_server, n1 };
	}

	/**
    * @brief Computes the public modulus and checks the client and server moduli
	* for correct bit length and comprimality.
    * 
    * @param n1 - client modulus
    * @param n2 - server modulus
    * @return public modulus
    * @throws std::out_of_range public modulus has got wrong bit length
    * @throws std::runtime_error if a Bignum error occurs
    */
	Bignum multiply_and_check_moduli(const Bignum& n1, const Bignum& n2) {
		std::cout << "Computing public key...";

		check_num_bits(n1, RSA_MODULUS_BITS);
		check_num_bits(n2, RSA_MODULUS_BITS);

		if (Bignum::gcd(n1, n2) != 1)
			throw std::runtime_error("Client and server moduli must be comprime!");
		
		Bignum n = n1 * n2;
		check_num_bits(n, RSA_MODULUS_BITS * 2);

		std::cout << "\x1B[1;32mOK\x1B[0m\n";
		return n;
	}

	/**
 	* @brief Saves generated keys to corresponding files, one for the server
 	* itself and the other for general public.
 	* 
 	* @param d1_server - server share of the client private exponent (d''_1)
 	* @param n1 - client modulus
    * @param d2 - server private exponent (d_2)
 	* @param n1 - client modulus
    * @param n - public modulus
 	* @throws std::runtime_exception if an IO problem occurs
 	* @throws std::out_of_range if the client modulus bit length test fails
 	*/
	void save_keys(const Bignum& d1_server, const Bignum& n1,
	    const Bignum& d2, const Bignum& n2, const Bignum& n) {
		std::cout << "Storing keys... ";

		std::ofstream server(SERVER_KEYS_FILE), public_key(PUBLIC_KEY_FILE);
		if (!server || !public_key)
			throw std::runtime_error("Could not save the keys!");

		server << d1_server << '\n'
		       << n1 << '\n'
		       << d2 << '\n'
		       << n2 << '\n';

		public_key << std::hex << RSA_PUBLIC_EXP << std::dec << '\n'
		           << n << '\n';

		if (!server || !public_key)
			throw std::runtime_error("Could not save the keys!");

		std::cout << "\x1B[1;32mOK\x1B[0m\n";
	}
};

#endif // SERVER_COMMON_HPP
