#include "bignum_wrapper.hpp"

Bignum_CTX Bignum::ctx;

void handleError(bool errCode) {
	if (!errCode)
		throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
}

Bignum_CTX::Bignum_CTX()
    : value(BN_CTX_new()) { // BN_CTX_secure_new()
	handleError(value);
}

BN_CTX* Bignum_CTX::get() {
	return value;
}

Bignum_CTX::~Bignum_CTX() {
	BN_CTX_free(value);
}

std::ostream& operator<<(std::ostream& os, const Bignum& bn) {
	char* const dec = BN_bn2hex(bn.get());
	handleError(dec);

	os << std::string(dec);

	OPENSSL_free(dec);
	return os;
}

std::istream& operator>>(std::istream& is, Bignum& bn) {
	std::string tmp;

	is >> tmp;
	bn.set(tmp);

	return is;
}

bool operator==(const Bignum& a, const Bignum& b) {
	return BN_cmp(a.get(), b.get()) == 0;
}

bool operator!=(const Bignum& a, const Bignum& b) {
	return !(a == b);
}

Bignum operator+(const Bignum& a, const Bignum& b) {
	Bignum r;
	handleError(BN_add(r.get(), a.get(), b.get()));

	return r;
}

Bignum operator-(const Bignum& a, const Bignum& b) {
	Bignum r;
	handleError(BN_sub(r.get(), a.get(), b.get()));

	return r;
}

Bignum operator*(const Bignum& a, const Bignum& b) {
	Bignum r;
	handleError(BN_mul(r.get(), a.get(), b.get(), Bignum::ctx.get()));

	return r;
}

Bignum::Bignum()
    : value(BN_new()) { // BN_CTX_secure_new()
	handleError(value);
}

Bignum::Bignum(unsigned long word)
    : Bignum() {
	handleError(BN_set_word(value, word));
}

Bignum::Bignum(const std::string& word)
    : Bignum() {
	handleError(BN_dec2bn(&value, word.c_str()));
}

Bignum::Bignum(const Bignum& other)
    : value(BN_dup(other.get())) {
	handleError(value);
}

Bignum::Bignum(const BIGNUM* other)
    : value(BN_dup(other)) {
	handleError(value);
}

Bignum& Bignum::operator=(Bignum other) {
	swap(other);
	return *this;
}

void Bignum::swap(Bignum& other) {
	std::swap(value, other.value);
}

BIGNUM* Bignum::get() {
	return value;
}

const BIGNUM* Bignum::get() const {
	return value;
}

// TODO: Bn_rand
void Bignum::set_random_value(int bits) {
	handleError(BN_rand(value, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY));
}

bool Bignum::check_num_bits(int length) const {
	return BN_num_bits(value) == length;
}

bool Bignum::is_one() const {
	return BN_is_one(value);
}

Bignum Bignum::inverse(const Bignum& num, const Bignum& mod) {
	Bignum res;
	handleError(BN_mod_inverse(res.get(), num.get(), mod.get(), ctx.get()));

	return res;
}

Bignum Bignum::gcd(const Bignum& a, const Bignum& b) {
	Bignum res;
	handleError(BN_gcd(res.get(), a.get(), b.get(), ctx.get()));

	return res;
}

Bignum Bignum::mod_sub(const Bignum& a, const Bignum& b, const Bignum& mod) {
	Bignum res;
	handleError(BN_mod_sub(res.get(), a.get(), b.get(), mod.get(), ctx.get()));

	return res;
}

Bignum Bignum::mod_exp(const Bignum& a, const Bignum& b, const Bignum& mod) {
	Bignum res;
	handleError(BN_mod_exp(res.get(), a.get(), b.get(), mod.get(), ctx.get()));

	return res;
}

void Bignum::mod_mul_self(const Bignum& a, const Bignum& mod) {
	handleError(BN_mod_mul(value, value, a.get(), mod.get(), ctx.get()));
}

void Bignum::set(unsigned long word) {
	handleError(BN_set_word(value, word));
}

void Bignum::set(const std::string& hexWord) {
	handleError(BN_hex2bn(&value, hexWord.c_str()));
}

Bignum::~Bignum() {
	BN_free(value); // BN_clear_free()
}

Bignum& Bignum::operator+=(const Bignum& a) {
	handleError(BN_add(value, value, a.get()));
	return *this;
}

Bignum& Bignum::operator+=(unsigned long a) {
	handleError(BN_add_word(value, a));
	return *this;
}

Bignum& Bignum::operator-=(const Bignum& a) {
	handleError(BN_sub(value, value, a.get()));
	return *this;
}

Bignum& Bignum::operator-=(unsigned long a) {
	handleError(BN_sub_word(value, a));
	return *this;
}

Bignum& Bignum::operator*=(const Bignum& a) {
	handleError(BN_mul(value, value, a.get(), ctx.get()));
	return *this;
}

Bignum& Bignum::operator*=(unsigned long a) {
	handleError(BN_mul_word(value, a));
	return *this;
}

Bignum& Bignum::operator--() {
	handleError(BN_sub_word(value, 1ul));
	return *this;
}

Bignum Bignum::operator--(int) {
	Bignum copy{ *this };
	--*this;

	return copy;
}

Bignum& Bignum::operator++() {
	handleError(BN_add_word(value, 1ul));
	return *this;
}

Bignum Bignum::operator++(int) {
	Bignum copy{ *this };
	++*this;

	return copy;
}