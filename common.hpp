#ifndef COMMON_HPP
#define COMMON_HPP

#include "bignum_wrapper.hpp"
#include "rsa_wrapper.hpp"

// Workaround for clang-tidy [cppcoreguidelines-interfaces-global-init]
#define RSA_PUBLIC_KEY 65537

class RSA_Keys {
private:
	static const unsigned TEST_COUNT{ 1000 };

public:
	static const unsigned RSA_MODULUS_BITS{ 4096 };
	static const Bignum e;

	/**
    * Generates required for encryption.
    */
	void generate_RSA_keys();

	const Bignum& get_d_client() const;
	const Bignum& get_d_server() const;
	const Bignum& get_n() const;

	void set_d_client(const Bignum& num);

	/**
    * Runs self-test
    */
	bool run_test();

private:
	Bignum d_client;
	Bignum d_server;
	Bignum n;

	bool is_test{ false };

	void e_coprimality_test(const Bignum& num);

	void generate_public_modulus(const Bignum& p, const Bignum& q);
	void generate_private_key(const Bignum& phi_p, const Bignum& phi_q);
};

void check_num_bits(const Bignum& num, unsigned long bits);

/**
 * Checks whether the given keys have been already generated.
 */
bool regeneration();

#endif // COMMON_HPP
