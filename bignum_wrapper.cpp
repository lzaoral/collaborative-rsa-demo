#include "bignum_wrapper.hpp"

/*********************************
 * Bignum wrapper implementation *
 ********************************/

Bignum_CTX::Bignum_CTX() : value(BN_CTX_secure_new())
{
    handle_error(value);
}

BN_CTX *Bignum_CTX::get()
{
    return value;
}

Bignum_CTX::~Bignum_CTX()
{
    BN_CTX_free(value);
}

/*********************************
 * Bignum wrapper implementation *
 ********************************/

// Initialisation of a static member of the Bignum class
Bignum_CTX Bignum::ctx;

std::ostream &operator<<(std::ostream &os, const Bignum &bn)
{
    char *const dec = BN_bn2hex(bn.get());
    if (!dec) {
        os.setstate(std::ios::failbit);
    }

    os << std::string(dec);

    OPENSSL_free(dec);
    return os;
}

std::istream &operator>>(std::istream &is, Bignum &bn)
{
    std::string tmp;

    is >> tmp;
    try {
        bn.set(tmp, true);
    } catch (std::runtime_error &e) {
        is.setstate(std::ios::failbit);
    }

    return is;
}

bool operator==(const Bignum &a, const Bignum &b)
{
    return BN_cmp(a.get(), b.get()) == 0;
}

bool operator!=(const Bignum &a, const Bignum &b)
{
    return !(a == b);
}

bool operator<(const Bignum &a, const Bignum &b)
{
    return BN_cmp(a.get(), b.get()) == -1;
}

bool operator>(const Bignum &a, const Bignum &b)
{
    return BN_cmp(a.get(), b.get()) == 1;
}

bool operator<=(const Bignum &a, const Bignum &b)
{
    return a < b || a == b;
}

bool operator>=(const Bignum &a, const Bignum &b)
{
    return a > b || a == b;
}

Bignum operator+(const Bignum &a, const Bignum &b)
{
    Bignum r;
    handle_error(BN_add(r.get(), a.get(), b.get()));

    return r;
}

Bignum operator-(const Bignum &a, const Bignum &b)
{
    Bignum r;
    handle_error(BN_sub(r.get(), a.get(), b.get()));

    return r;
}

Bignum operator*(const Bignum &a, const Bignum &b)
{
    Bignum r;
    handle_error(BN_mul(r.get(), a.get(), b.get(), Bignum::ctx.get()));

    return r;
}

Bignum::Bignum() : value(BN_secure_new())
{
    handle_error(value);
}

Bignum::Bignum(unsigned long word) : Bignum()
{
    handle_error(BN_set_word(value, word));
}

Bignum::Bignum(const std::string &word, bool is_hex) : Bignum()
{
    if (is_hex) {
        handle_error(BN_hex2bn(&value, word.c_str()));
        return;
    }

    handle_error(BN_dec2bn(&value, word.c_str()));
}

Bignum::Bignum(const Bignum &other) : value(BN_dup(other.get()))
{
    handle_error(value);
}

Bignum::Bignum(const BIGNUM *other) : value(BN_dup(other))
{
    handle_error(value);
}

Bignum &Bignum::operator=(Bignum other)
{
    swap(other);
    return *this;
}

void Bignum::swap(Bignum &other)
{
    std::swap(value, other.value);
}

BIGNUM *Bignum::get()
{
    return value;
}

const BIGNUM *Bignum::get() const
{
    return value;
}

void Bignum::set_random_value(int bits)
{
    handle_error(BN_rand(value, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY));
}

bool Bignum::check_num_bits(int length) const
{
    return BN_num_bits(value) == length;
}

bool Bignum::is_one() const
{
    return BN_is_one(value);
}

void Bignum::mod(const Bignum &mod)
{
    handle_error(BN_mod(value, value, mod.get(), ctx.get()));
}

Bignum Bignum::inverse(const Bignum &num, const Bignum &mod)
{
    Bignum res;
    handle_error(BN_mod_inverse(res.get(), num.get(), mod.get(), ctx.get()));

    return res;
}

Bignum Bignum::gcd(const Bignum &a, const Bignum &b)
{
    Bignum res;
    handle_error(BN_gcd(res.get(), a.get(), b.get(), ctx.get()));

    return res;
}

Bignum Bignum::mod_sub(const Bignum &a, const Bignum &b, const Bignum &mod)
{
    Bignum res;
    handle_error(BN_mod_sub(res.get(), a.get(), b.get(), mod.get(), ctx.get()));

    return res;
}

Bignum Bignum::mod_exp(const Bignum &a, const Bignum &b, const Bignum &mod)
{
    Bignum res;
    handle_error(BN_mod_exp(res.get(), a.get(), b.get(), mod.get(), ctx.get()));

    return res;
}

void Bignum::mod_mul_self(const Bignum &a, const Bignum &mod)
{
    handle_error(BN_mod_mul(value, value, a.get(), mod.get(), ctx.get()));
}

void Bignum::set(unsigned long word)
{
    handle_error(BN_set_word(value, word));
}

void Bignum::set(const std::string &word, bool is_hex)
{
    if (is_hex) {
        handle_error(BN_hex2bn(&value, word.c_str()));
        return;
    }

    handle_error(BN_dec2bn(&value, word.c_str()));
}

Bignum::~Bignum()
{
    BN_clear_free(value);
}

Bignum &Bignum::operator+=(const Bignum &a)
{
    handle_error(BN_add(value, value, a.get()));
    return *this;
}

Bignum &Bignum::operator+=(unsigned long a)
{
    handle_error(BN_add_word(value, a));
    return *this;
}

Bignum &Bignum::operator-=(const Bignum &a)
{
    handle_error(BN_sub(value, value, a.get()));
    return *this;
}

Bignum &Bignum::operator-=(unsigned long a)
{
    handle_error(BN_sub_word(value, a));
    return *this;
}

Bignum &Bignum::operator*=(const Bignum &a)
{
    handle_error(BN_mul(value, value, a.get(), ctx.get()));
    return *this;
}

Bignum &Bignum::operator*=(unsigned long a)
{
    handle_error(BN_mul_word(value, a));
    return *this;
}

Bignum &Bignum::operator--()
{
    handle_error(BN_sub_word(value, 1ul));
    return *this;
}

Bignum Bignum::operator--(int)
{
    Bignum copy{*this};
    --*this;

    return copy;
}

Bignum &Bignum::operator++()
{
    handle_error(BN_add_word(value, 1ul));
    return *this;
}

Bignum Bignum::operator++(int)
{
    Bignum copy{*this};
    ++*this;

    return copy;
}

/********************
 * Helper functions *
 *******************/

void handle_error(bool return_code)
{
    if (!return_code)
        throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
}
