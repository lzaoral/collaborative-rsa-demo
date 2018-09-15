#include <stdbool.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "common_client.h"

int generateRSAKeys() {

    BN_CTX *ctx = BN_CTX_secure_new();

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

        BN_free(p);

        return EXIT_FAILURE;
    }

    printf("(2^%d-2^%d)-safe primes generated!\n\n", RSA_L_BITS, RSA_S_BITS);
    printf("p: %s\n\nq: %s\n\n", BN_bn2dec(p), BN_bn2dec(q));

    BIGNUM *n = BN_secure_new();
    
    if (!n) {
        /* code */
    }
    
    if (!BN_mul(n, p, q, ctx)) {
        BN_free(p);
        BN_free(q);
        BN_CTX_free(ctx);
    }

    BIGNUM *pMinusOne = BN_dup(p);

    if (!pMinusOne) {
        /* code */
    }

    if (!BN_sub_word(pMinusOne, 1)) {
        /* code */
    }

    BIGNUM *qMinusOne = BN_dup(q);
    
    if (!qMinusOne) {
        /* code */
    }
    
    if (!BN_sub_word(qMinusOne, 1)) {
        /* code */
    }

    BIGNUM *phiN = BN_secure_new();

    if (!phiN) {
        /* code */
    }

    if (!BN_mul(phiN, pMinusOne, qMinusOne, ctx)) {
        /* code */
    }
    
    BIGNUM *e = NULL;
    if (!BN_dec2bn(&e, RSA_PUBLIC_KEY)) {
        
        BN_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    BIGNUM *d = BN_secure_new();
    
    if (!d) {
        /* code */
    }
    
    if (!BN_mod_inverse(d, e, phiN, ctx)) {
        /* code */
    }
    
    printf("Private key: %s\n\n", BN_bn2dec(d));
    return EXIT_SUCCESS;
}


int generateLSSafePrime(BIGNUM **safePrime) {

    BN_CTX *tempBN = BN_CTX_secure_new();

    if (!tempBN) {
        /* code */
    }
    

    BIGNUM *tmp = NULL;
    BIGNUM *e = NULL;

    if (!BN_dec2bn(&e, RSA_PUBLIC_KEY)) {
        
        BN_CTX_free(tempBN);
        return EXIT_FAILURE;
    }

    while (true) {
        
        // GENERATE RANDOM S-PRIMES
        unsigned char count = 5;      

        // TODO: random count?

        /*
        if (!RAND_bytes(&count, 1)) {
            printf("neco se posralo\n");
            getchar();

            BN_clear_free(tmp);
            BN_CTX_free(tempBN);

            return EXIT_FAILURE;
        }*/
        
        BIGNUM *primes[count];

        for (size_t i = 0; i < count; i++) {
            
            if (!(primes[i] = BN_new())) {
               for (size_t k = 0; k < i; k++) {
                    BN_free(primes[k]);
                }
            }

            unsigned char sbitCount = 0;

            do {
                if (!RAND_bytes(&sbitCount, 1)) {
                    printf("neco se posralo\n");
                    getchar();

                    BN_clear_free(tmp);
                    BN_CTX_free(tempBN);

                    for (size_t k = 0; k < i; k++) {
                        BN_free(primes[k]);
                    }

                    return EXIT_FAILURE;
                }
            } while (sbitCount < RSA_S_BITS);
                       
            if (!BN_generate_prime_ex(primes[i], sbitCount, 0, NULL, NULL, NULL)) {
                for (size_t k = 0; k <= i; k++) {
                    BN_free(primes[k]);
                }
                
                goto err;
            }
        }
        
        // MULTIPLY ALL S-PRIMES
        if (!BN_dec2bn(&tmp, "1")) {
            for (size_t i = 0; i < count; i++) {
                BN_clear_free(primes[i]);
            }   

            goto err;
        }
        
        for (size_t i = 0; i < count; i++) {
            if (!BN_mul(tmp, primes[i], tmp, tempBN)) {
                for (size_t k = 0; k < i; k++) {
                    BN_clear_free(primes[k]);
                }
                
                goto err;
            }            
        }

        for (size_t i = 0; i < count; i++) {
            BN_clear_free(primes[i]);
        }

        // MULTIPLY WITH RANDOM 1 <= a <= L a and 2 and then add 1 
        unsigned char aBuffer[RSA_L_BITS / 8];
        
        if (!RAND_bytes(aBuffer, RSA_L_BITS / 8)) {
            goto err;
        }
        
        long a = 0;
        memcpy(&a, aBuffer, RSA_L_BITS / 8);

        if (!BN_mul_word(tmp, a * 2)) {
            goto err;
        }

        BIGNUM *tmpMinOne = BN_dup(tmp);
        if (!tmpMinOne) {
            goto err;
        }
        
        if (!BN_add_word(tmp, 1)) {
            goto err;
        }

        // PRIMALITY TEST
        if (BN_is_prime_ex(tmp, BN_prime_checks, tempBN, NULL) == 1) {
            
            BIGNUM *one = NULL;
            if (!BN_dec2bn(&one, "1")) {
                goto err;
            }
            

            if (!BN_gcd(tmpMinOne, e, one, tempBN)) {
                goto err;
            }

            
            if (BN_is_one(tmpMinOne)) {
                *safePrime = tmp;
                tmp = NULL;

                BN_free(tmpMinOne);

                printf("Found a (2^%d-2^%d)-prime coprime with e: %s\n\n\n", RSA_L_BITS, RSA_S_BITS, BN_bn2dec(*safePrime));

                BN_CTX_free(tempBN);

                return EXIT_SUCCESS;
            }

            printf("Found prime, that is not coprime to e.\n\n");
        }

        BN_free(tmpMinOne);
        continue;        

    err:
        printf("neco se posralo\n");
        getchar();

        BN_clear_free(tmp);
        BN_CTX_free(tempBN);

        return EXIT_FAILURE;
    }

    // TODO: ugly
    return EXIT_FAILURE;
}
