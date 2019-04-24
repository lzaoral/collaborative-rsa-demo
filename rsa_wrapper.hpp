#ifndef RSA_WRAPPER_HPP
#define RSA_WRAPPER_HPP

#include "bignum_wrapper.hpp"

#include <openssl/rsa.h>
#include <vector>

/**
 * @brief Wrapper of the RSA struct and used RSA operations 
 * defined in the OPENSSL library.
 */
class Rsa {
private:
	RSA* value;

public:
	Rsa(Bignum e, int bits, int primes)
	    : value(RSA_new()) {

		handle_error(value);
		handle_error(RSA_generate_multi_prime_key(value, bits, primes, e.get(), nullptr));
	}

	std::pair<Bignum, Bignum> getPrimes() const {
		std::vector<const BIGNUM*> primes(RSA_get_multi_prime_extra_count(value) + 2);
		handle_error(RSA_get0_multi_prime_factors(value, primes.data()));

		return { primes[0], primes[1] };
	}

	~Rsa() {
		RSA_free(value);
	}
};

#endif // RSA_WRAPPER_HPP
