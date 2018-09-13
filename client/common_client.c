#include <stdbool.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "common_client.h"

int generateRSAKeys() {

    BIGNUM *p = NULL;
    BIGNUM *q = NULL;

    printf("Generating p...");
    if (generateLSSafePrime(&p)) {
        printf("neco se posralo\n");
        getchar();
        return EXIT_FAILURE;
    }

    printf("Generating q...");
    if (generateLSSafePrime(&q)) {
        printf("neco se posralo\n");
        getchar();
        return EXIT_FAILURE;
    }

    printf("Key generated!\n");
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
        
        /*
        for (size_t i = 0; i < count; i++) {
            char *string = BN_bn2dec(primes[i]);
            printf("Cislo %d: %s\n", (int) i + 1, string);
        }
        */

        // MULTIPLY ALL L-PRIMES
        if (!BN_dec2bn(&tmp, "1")) {
            goto err;
        }
        
        for (size_t i = 0; i < count; i++) {
            if (!BN_mul(tmp, primes[i], tmp, tempBN)) {
                goto err;
            }            
        }

        // printf("Cislo: %s\n", BN_bn2dec(tmp));

        // MULTIPLY WITH RANDOM a, two and add 1 
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

        // printf("Cislo: %s\n", BN_bn2dec(tmp));

        for (size_t i = 0; i < count; i++) {
            BN_free(primes[i]);
        }

        // PRIMALITY TEST
        if (BN_is_prime_ex(tmp, BN_prime_checks, tempBN, NULL) == 1) {
            isSafe = true;
            *safePrime = tmp;
            tmp = NULL;

            printf("Found a (%d-%d)-prime: %s\n", RSA_L_BITS, RSA_S_BITS, BN_bn2dec(*safePrime));
            getchar();
            getchar();
            getchar();

            BN_CTX_free(tempBN);

            return EXIT_SUCCESS;
        }

        continue;

        // TODO: lol
        return EXIT_FAILURE;
        /*printf("Su vnu\n");

        getchar();

        if (!BN_generate_prime_ex(safePrime, 2048, 0, NULL, NULL, NULL)) {
            goto err;
        }

        char *string = BN_bn2dec(safePrime);
        printf("Cislo: %s\n", string);

        getchar();

        // subtract one
        BIGNUM *one;

        if (!BN_dec2bn(&one, "1")) {
            goto err;
        }        

        if (!BN_sub(safePrime, safePrime, one)) {
            goto err;
        }

        string = BN_bn2dec(safePrime);
        printf("Cislo - 1: %s\n", string);

        getchar();

        // divide by two      
        if (!BN_rshift1(safePrime, safePrime)) {
            goto err;
        }

        string = BN_bn2dec(safePrime);
        printf("(Cislo - 1) / 2: %s\n", string);

        getchar();
        */



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
