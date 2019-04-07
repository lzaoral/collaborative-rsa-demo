#ifndef BIGNUM_WRAPPER_HPP
#define BIGNUM_WRAPPER_HPP

#include <openssl/bn.h>
#include <openssl/err.h>

#include <iostream>

void handleError(bool errCode);

class Bignum_CTX {
private:
	BN_CTX* const value;

public:
	Bignum_CTX();
	~Bignum_CTX();

	BN_CTX* get();
};

class Bignum {
private:
	BIGNUM* value;

	friend std::ostream& operator<<(std::ostream& os, const Bignum& bn);
	friend std::istream& operator>>(std::istream& is, Bignum& bn);

	friend bool operator==(const Bignum& a, const Bignum& b);
	friend bool operator!=(const Bignum& a, const Bignum& b);

	friend Bignum operator+(const Bignum& a, const Bignum& b);
	friend Bignum operator-(const Bignum& a, const Bignum& b);
	friend Bignum operator*(const Bignum& a, const Bignum& b);

public:
	static Bignum_CTX ctx;

	Bignum();
	Bignum(unsigned long word);
	Bignum(const std::string& word);

	Bignum(const Bignum& other);
	Bignum(const BIGNUM* other);

	~Bignum();

	Bignum& operator=(Bignum other);
	void swap(Bignum& other);

	Bignum& operator+=(const Bignum& a);
	Bignum& operator+=(unsigned long a);
	Bignum& operator-=(const Bignum& a);
	Bignum& operator-=(unsigned long a);
	Bignum& operator*=(const Bignum& a);
	Bignum& operator*=(unsigned long a);

	Bignum& operator--();
	Bignum& operator++();
	Bignum operator--(int);
	Bignum operator++(int);

	static Bignum inverse(const Bignum& num, const Bignum& mod);
	static Bignum gcd(const Bignum& a, const Bignum& b);
	static Bignum mod_sub(const Bignum& a, const Bignum& b, const Bignum& mod);
	static Bignum mod_exp(const Bignum& a, const Bignum& b, const Bignum& mod);
	void mod_mul_self(const Bignum& a, const Bignum& mod);

	BIGNUM* get();
	const BIGNUM* get() const;

	void set(unsigned long word);
	void set(const std::string& word);

	// TODO: Bn_rand
	void set_random_value(int bits);
	bool check_num_bits(int length) const;
	bool is_one() const;
};

#endif // BIGNUM_WRAPPER_HPP