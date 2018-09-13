#include <stdbool.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "common_client.h"

int generateRSAKeys() {

    BIGNUM *p = NULL;
    BIGNUM *q = NULL;

    printf("Generating p...\n");
    if (generateLSSafePrime(&p)) {
        printf("neco se posralo\n");
        getchar();
        return EXIT_FAILURE;
    }

    printf("Generating q...\n");
    if (generateLSSafePrime(&q)) {
        printf("neco se posralo\n");
        getchar();
        return EXIT_FAILURE;
    }

    printf("(2^%d-2^%d)-safe primes generated!\n", RSA_L_BITS, RSA_S_BITS);
    printf("p: %s\nq: %s\n", BN_bn2dec(p), BN_bn2dec(q));

    getchar();

    return EXIT_SUCCESS;
}


int generateLSSafePrime(BIGNUM **safePrime) {

    bool isSafe = false;
    BN_CTX *tempBN = BN_CTX_secure_new();
    BIGNUM *tmp = NULL;

    while (!isSafe) {
        
        // GENERATE RANDOM L-PRIMES
        const int count = 10;
        BIGNUM *primes[count];

        // TODO: use random count and RSA_S_BITS as minimum
        for (size_t i = 0; i < count; i++) {
            primes[i] = BN_new();           

            if (!BN_generate_prime_ex(primes[i], RSA_S_BITS, 0, NULL, NULL, NULL)) {
                goto err;
            }
        }
        
        // MULTIPLY ALL L-PRIMES
        if (!BN_dec2bn(&tmp, "1")) {
            goto err;
        }
        
        for (size_t i = 0; i < count; i++) {
            if (!BN_mul(tmp, primes[i], tmp, tempBN)) {
                goto err;
            }            
        }

        for (size_t i = 0; i < count; i++) {
            BN_free(primes[i]);
        }

        // MULTIPLY WITH RANDOM S >= a and 2 and then add 1 
        unsigned char aBuffer[RSA_L_BITS / 8];
        
        if (!RAND_bytes(aBuffer, RSA_L_BITS / 8)) {
            goto err;
        }
        
        long a = 0;
        memcpy(&a, aBuffer, RSA_L_BITS / 8);

        if (!BN_mul_word(tmp, a)) {
            goto err;
        }
        
        if (!BN_mul_word(tmp, 2)) {
            goto err;
        }

        if (!BN_add_word(tmp, 1)) {
            goto err;
        }

        

        // PRIMALITY TEST
        if (BN_is_prime_ex(tmp, BN_prime_checks, tempBN, NULL) == 1) {
            isSafe = true;
            *safePrime = tmp;
            tmp = NULL;

            printf("Found a (2^%d-2^%d)-prime: %s\n\n\n", RSA_L_BITS, RSA_S_BITS, BN_bn2dec(*safePrime));

            BN_CTX_free(tempBN);

            return EXIT_SUCCESS;
        }

        continue;        

    err:
        printf("neco se posralo\n");
        getchar();

        if (!tmp) {
            BN_free(tmp);
        }     

        BN_CTX_free(tempBN);

        return EXIT_FAILURE;
    }

    // TODO: ugly
    return EXIT_FAILURE;
}
