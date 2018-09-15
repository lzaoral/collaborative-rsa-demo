#ifndef COMMON_CLIENT_H
#define COMMON_CLIENT_H

#define RSA_L_BITS 16
#define RSA_S_BITS 200
#define RSA_MODULUS_BITS // TODO: ???
#define RSA_PUBLIC_KEY "853"

#define SECURITY_BITS 112

/**
 * Generates and stores keys required for encryption.
 */
int generateRSAKeys();

/**
 * Generates an (l,s)-safe prime number
 */
int generateLSSafePrime();

#endif // COMMON_CLIENT_H
