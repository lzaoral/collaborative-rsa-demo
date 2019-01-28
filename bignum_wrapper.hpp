#ifndef BIGNUM_WRAPPER_HPP
#define BIGNUM_WRAPPER_HPP

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdexcept>

class Bignum {
private:
	BIGNUM* value;

	friend std::ostream& operator<<(std::ostream& os, const Bignum& bn) {
		char* const dec = BN_bn2dec(bn.get());
		if (!dec)
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));

		os << dec;

		OPENSSL_free(dec);

		return os;
	}

	friend std::istream& operator>>(std::istream& is, Bignum& bn) {
		std::string tmp;

		is >> tmp;
		bn.set(tmp);

		return is;
	}

public:
	Bignum()
	    : value(BN_new()) { // BN_CTX_secure_new()

		if (!value)
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
	}

	Bignum(unsigned long word)
	    : Bignum() {

		if (!BN_set_word(value, word))
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
	}

	Bignum(const std::string& word)
	    : Bignum() {

		if (!BN_dec2bn(&value, word.c_str()))
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
	}

	Bignum(const Bignum& other)
	    : value(BN_dup(other.get())) {
		if (!value)
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
	}

	Bignum(const BIGNUM* other)
	    : value(BN_dup(other)) {}

	Bignum& operator=(const Bignum& other) {
		if (this == &other)
			return *this;

		BN_free(value);
		value = BN_dup(other.get());

		if (!value)
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));

		return *this;
	}

	BIGNUM* get() {
		return value;
	}

	const BIGNUM* get() const {
		return value;
	}

	void set(unsigned long word) {
		if (!BN_set_word(value, word))
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
	}

	void set(const std::string& word) {
		if (!BN_dec2bn(&value, word.c_str()))
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
	}

	~Bignum() {
		BN_free(value); // BN_clear_free()
	}
};

class Bignum_CTX {
private:
	BN_CTX* const value;

public:
	Bignum_CTX()
	    : value(BN_CTX_new()) { // BN_CTX_secure_new()
		if (!value)
			throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
	}

	BN_CTX* get() {
		return value;
	}

	~Bignum_CTX() {
		BN_CTX_free(value);
	}
};

#endif // BIGNUM_WRAPPER_HPP