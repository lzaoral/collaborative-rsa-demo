#ifndef COMMON_CLIENT_H
#define COMMON_CLIENT_H

#define RSA_L_BITS 16
#define RSA_S_BITS 200
#define RSA_MODULUS_BITS // TODO: ???
#define RSA_PUBLIC_KEY 853

#define SECURITY_BITS 112

/**
 * Generates and stores keys required for encryption.
 */
int generateRSAKeys(BIGNUM **e, BIGNUM **d, BIGNUM **n);

/**
 * Generates an (l,s)-safe prime number
 */
int generateLSSafePrime(BIGNUM const *const e, BIGNUM **const safePrime, BIGNUM **const phiSafePrime, BN_CTX *const ctx);

/**
 * 
 */
int runTest();

#endif // COMMON_CLIENT_H
