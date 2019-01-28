#ifndef RSA_WRAPPER_HPP
#define RSA_WRAPPER_HPP

#include "bignum_wrapper.hpp"
#include "common.hpp"
#include <openssl/rsa.h>

class Rsa {
private:
	RSA* value;

public:
	Rsa(Bignum e)
	    : value(RSA_new()) {

		if (!value)
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));

		handleError(RSA_generate_multi_prime_key(value, RSA_Keys::RSA_MODULUS_BITS, 4, e.get(), nullptr));
	}

	std::pair<Bignum, Bignum> getPrimes() const {
		std::vector<const BIGNUM*> primes(RSA_get_multi_prime_extra_count(value));
		handleError(RSA_get0_multi_prime_factors(value, primes.data()));

		return { Bignum{ primes[0] }, Bignum{ primes[1] } };
	}

	~Rsa() {
		RSA_free(value);
	}
};

#endif // RSA_WRAPPER_HPP