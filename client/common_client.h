#ifndef COMMON_CLIENT_H
#define COMMON_CLIENT_H

#define RSA_L 65536
#define RSA_S 1.606938e+60
#define RSA_MODULUS

#define SECURITY_BITS 112

/**
 * Generates and stores keys required for encryption.
 */
int generateRSAKeys();

/**
 * Generates an (l,s)-dafe prime number
 */
int generateLSSafePrime();

#endif // COMMON_CLIENT_H
