#ifndef COMMON_HPP
#define COMMON_HPP

#include "bignum_wrapper.hpp"
#include "rsa_wrapper.hpp"

#define CLIENT_KEYS_CLIENT_FILE "client_card.key"
#define CLIENT_KEYS_SERVER_FILE "for_server.key"
#define SERVER_KEYS_FILE "server.key"

#define MESSAGE_FILE "message.txt"
#define CLIENT_SIG_SHARE_FILE "client.sig"
#define FINAL_SIG_FILE "final.sig"

#define PUBLIC_KEY_FILE "public_key.key"

#define RSA_PRIME_COUNT 4
#define RSA_PUBLIC_EXP 65537
#define RSA_MODULUS_BITS 2048

class RSA_keys_generator {
private:
	static const unsigned TEST_COUNT{ 1000 };

public:
	/**
	 * Defult constructor assumes the client environment.
	 */
	RSA_keys_generator() = default;

	/**
	 * Construts the client/server RSA key generator depending
	 * on the server parameter.
	 * 
	 * @param server sets the server environment
	 */
	RSA_keys_generator(bool server)
	    : is_server(server) {}

	/**
    * Generates needed RSA keys. If the server attribute is true,
	* the private exponent is not divided and is set in the d_server
	* attribute instead.
	*
	* @throws std::runtime_exception if some Bignum operation failed
    */
	void generate_RSA_keys();

	/**
	 * Returns the client share of the client private exponent.
	 * If the server attribute is true, returns Bignum with zero value.
	 * 
	 * @return 
	 */
	const Bignum& get_d_client() const;
	const Bignum& get_d_server() const;
	const Bignum& get_n() const;

	/**
    * Runs self-test. Test count is set in the TEST_COUNT attribute.
    */
	void run_test();

private:
	Bignum d_client;
	Bignum d_server;
	Bignum n;

	bool is_server{ false };
	bool is_test{ false };

	void e_coprimality_test(const Bignum& num);
	void generate_modulus(const Bignum& p, const Bignum& q);
	void generate_private_key(const Bignum& phi_p, const Bignum& phi_q);
};

/**
 * Checks given Bignum if it has got the needed bit length.
 * 
 * @param num Bignum to be checked
 * @param bits expected bit length
 * @throws std::out_of_range if the check fails
 */
void check_num_bits(const Bignum& num, unsigned long bits);

/**
 * Checks that the message and the modulus meet given conditions.
 * Modulus has got the needed bit length and message is not greater
 * than the modulus.
 * 
 * @throws std::out_of_range if the check fails
 */
void check_message_and_modulus(const Bignum& message, const Bignum& n);

/**
 * Asks the user whether he wishes to regenerate the keys.
 * 
 * @return user choice
 * @throws std::runtime_exception if an IO problem occurs
 */
bool regeneration();

#endif // COMMON_HPP
