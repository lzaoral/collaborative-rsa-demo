#ifndef COMMON_HPP
#define COMMON_HPP

#include "bignum_wrapper.hpp"
#include "rsa_wrapper.hpp"

#define CLIENT_KEYS_CLIENT_FILE "client_card.key"
#define CLIENT_KEYS_SERVER_FILE "for_server.key"
#define SERVER_KEYS_FILE "server.key"
#define PUBLIC_KEY_FILE "public_key.key"

#define MESSAGE_FILE "message.txt"
#define CLIENT_SIG_SHARE_FILE "client.sig"
#define FINAL_SIG_FILE "final.sig"

#define RSA_PRIME_COUNT 4u
#define RSA_PUBLIC_EXP 65537u
#define RSA_MODULUS_BITS 2048u

/**
 * @brief Abstract class representing a party (e.g. client) in this protocol.
 */
class SMPC_demo {
public:
	/**
 	 * @brief Generates the RSA keys of a given party.
     */
	virtual void generate_keys() = 0;

	/**
 	* @brief Performs a computation of a signature share of a given party
    */
	virtual void sign_message() = 0;

	/**
 	* @brief Verifies the given final signature.
 	* 
 	* @throws std::runtime_exception if an IO problem occurs or some Bignum
 	*     operation failed
 	* @throws std::out_of_range if an Bignum bit length test fails
 	*/
	void verify_final_signature();

	virtual ~SMPC_demo() = default;
};

/**
 * @brief Class representing the client or server generator of RSA keys.
 */
class RSA_keys_generator {
private:
	static const unsigned TEST_COUNT{ 1000 };

public:
	/**
	 * @brief Default constructor assumes the client environment.
	 */
	RSA_keys_generator() = default;

	/**
	 * @brief Construts the client/server RSA key generator
	 * depending on the is_server parameter.
	 */
	RSA_keys_generator(bool is_server)
	    : is_server(is_server) {}

	/**
    * @brief Generates needed RSA keys. If the server attribute
	* is true, the private exponent is not divided and is set
	* in the d_server attribute instead.
	*
	* @throws std::runtime_exception if some Bignum operation failed
    */
	void generate_RSA_keys();

	/**
	 * @brief Returns the client share of the client private
	 * exponent. (d'_1)
	 * 
	 * @return client share of the client private exponent
	 */
	const Bignum& get_d1_client() const;

	/**
	 * @brief Returns the server share of the client private
	 * exponent. (d''_1)
	 * 
	 * @return server share of the client private exponent
	 */
	const Bignum& get_d1_server() const;

	/**
	 * @brief Returns the server private exponent.
	 * 
	 * @return server private exponent
	 */
	const Bignum& get_d2() const;

	/**
	 * @brief Returns the modulus.
	 * 
	 * @return modulus
	 */
	const Bignum& get_n() const;

	/**
    * @brief Runs a self-test. Test count is set in the TEST_COUNT
	* attribute.
    */
	void run_test();

private:
	Bignum d1_client;
	Bignum d1_server;
	Bignum d2;
	Bignum n;

	bool is_server{ false };
	bool is_test{ false };

	void e_coprimality_test(const Bignum& num);
	void generate_modulus(const Bignum& p, const Bignum& q);
	void generate_private_key(const Bignum& phi_p, const Bignum& phi_q);
};

/**
 * @brief Checks that given Bignum has got the needed
 * bit length.
 * 
 * @param num Bignum to be checked
 * @param bits expected bit length
 * @throws std::out_of_range if the check fails
 */
void check_num_bits(const Bignum& num, unsigned long bits);

/**
 * @brief Checks that the message and the modulus meet
 * given conditions. Modulus has got the needed bit length
 * and message is not greater than the modulus.
 * 
 * @param message message
 * @param n modulus
 * @param bits needed modulus bit length
 * @throws std::out_of_range if the check fails
 */
void check_message_and_modulus(const Bignum& message, const Bignum& n, unsigned long bits);

/**
 * @brief Asks the user whether he wishes to regenerate the keys.
 * 
 * @return user choice
 * @throws std::runtime_exception if an IO problem occurs
 */
bool regenerate_keys();

#endif // COMMON_HPP
