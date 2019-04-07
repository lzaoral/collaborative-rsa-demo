#ifndef RSA_WRAPPER_HPP
#define RSA_WRAPPER_HPP

#include "bignum_wrapper.hpp"

#include <openssl/rsa.h>
#include <vector>

class Rsa {
private:
	RSA* value;
	static const int PRIME_COUNT = 4;

public:
	Rsa(Bignum e, int bits)
	    : value(RSA_new()) {
		
		handleError(value);
		handleError(RSA_generate_multi_prime_key(value, bits, PRIME_COUNT, e.get(), nullptr));
	}

	std::pair<Bignum, Bignum> getPrimes() const {
		std::vector<const BIGNUM*> primes(RSA_get_multi_prime_extra_count(value) + 2);
		handleError(RSA_get0_multi_prime_factors(value, primes.data()));

		return { primes[0], primes[1] };
	}

	~Rsa() {
		RSA_free(value);
	}
};

#endif // RSA_WRAPPER_HPP