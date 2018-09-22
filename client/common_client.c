#include <stdbool.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "common_client.h"

int generateRSAKeys() {


    // INITIALIZATION PHASE
    BIGNUM *backup = NULL;
    char *printSring = NULL;

    BN_CTX *const ctx = BN_CTX_secure_new();
    if (!ctx) {
        perror("BIGNUM CTX allocation failed.\n");
        return EXIT_FAILURE;
    }
    
    BIGNUM *const e = BN_secure_new();
    if (!e) {
        BN_CTX_free(ctx);

        perror("BIGNUM allocation failed.\n");
        return EXIT_FAILURE;
    }

    if (!BN_set_word(e, RSA_PUBLIC_KEY)) {
        BN_clear_free(e);
        BN_CTX_free(ctx);

        perror("Conversion of public key to BIGNUM failed\n");
        return EXIT_FAILURE;
    }
    

    // PRIMES GENERATION
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *phiP = NULL;
    BIGNUM *phiQ = NULL;

    printf("Generating p...\n");
    if (generateLSSafePrime(e, &p, &phiP, ctx)) {
        BN_clear_free(e);
        BN_CTX_free(ctx);

        perror("Could not generate p! :(\n");
        return EXIT_FAILURE;
    }

    printf("Generating q...\n");
    if (generateLSSafePrime(e, &q, &phiQ, ctx)) {
        BN_clear_free(e);
        BN_clear_free(p);
        BN_clear_free(phiP);
        BN_CTX_free(ctx);

        perror("Could not generate q! :(\n");
        return EXIT_FAILURE;
    }

    printf("(2^%d-2^%d)-safe primes generated!\n\n", RSA_L_BITS, RSA_S_BITS);


    // PUBLIC MODULUS GENERATION
    BIGNUM *const n = BN_secure_new();
    
    if (!n) {
        BN_clear_free(e);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(phiP);
        BN_clear_free(phiQ);
        
        BN_CTX_free(ctx);

        perror("BIGNUM allocation failed.\n");
        return EXIT_FAILURE;
    }
    
    backup = n;
    if (!BN_mul(n, p, q, ctx)) {
        BN_clear_free(backup);
        BN_clear_free(e);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(phiP);
        BN_clear_free(phiQ);
        
        BN_CTX_free(ctx);

        perror("Could not compute the public modulus.\n");
        return EXIT_FAILURE;
    }
    backup = NULL;

    printSring = BN_bn2dec(n);
    if (!printSring) {
        BN_clear_free(n);
        BN_clear_free(e);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(phiP);
        BN_clear_free(phiQ);
        
        BN_CTX_free(ctx);

        perror("Could not print out the public modulus.\n");
        return EXIT_FAILURE;
    }
    
    printf("Public modulus: %s\n\n", printSring);
    OPENSSL_clear_free(printSring, sizeof(*printSring));
    printSring = NULL;

    
    // PRIVATE KEY GENERATION
    BIGNUM *phiN = BN_secure_new();
    if (!phiN) {
        BN_clear_free(n);
        BN_clear_free(e);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(phiP);
        BN_clear_free(phiQ);

        BN_CTX_free(ctx);

        perror("BIGNUM allocation failed.\n");
        return EXIT_FAILURE;
    }

    backup = phiN;
    if (!BN_mul(phiN, phiP, phiQ, ctx)) {
        BN_clear_free(backup);
        BN_clear_free(n);
        BN_clear_free(e);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(phiP);
        BN_clear_free(phiQ);

        BN_CTX_free(ctx);

        perror("Could not compute phi of the public modulus.\n");
        return EXIT_FAILURE;
    }
    backup = NULL;

    BN_clear_free(phiP);
    BN_clear_free(phiQ);
    phiP = NULL;
    phiQ = NULL;

    BIGNUM *d = BN_secure_new();
    if (!d) {
        BN_clear_free(n);
        BN_clear_free(e);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(phiN);

        BN_CTX_free(ctx);

        perror("BIGNUM allocation failed.\n");
        return EXIT_FAILURE;
    }
    
    backup = d;
    if (!BN_mod_inverse(d, e, phiN, ctx)) {
        BN_clear_free(backup);
        BN_clear_free(n);
        BN_clear_free(e);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(phiN);

        BN_CTX_free(ctx);

        perror("Private key computation failed.\n");
        return EXIT_FAILURE;
    }
    backup = NULL;

    printSring = BN_bn2dec(d);
    if (!printSring) {
        BN_clear_free(d);
        BN_clear_free(n);
        BN_clear_free(e);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(phiN);

        BN_CTX_free(ctx);

        perror("Could not print out the private key.\n");
        return EXIT_FAILURE;
    }
    
    printf("Private key: %s\n\n", printSring);
    OPENSSL_clear_free(printSring, sizeof(*printSring));
    printSring = NULL;

    // TEMPORARY CLEANUP
    BN_clear_free(d);
    BN_clear_free(n);
    BN_clear_free(e);
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(phiN);

    BN_CTX_free(ctx);

    return EXIT_SUCCESS;
}


int generateLSSafePrime(BIGNUM *const e, BIGNUM **const safePrime, BIGNUM **const phiSafePrime, BN_CTX *const ctx) {
        
    BIGNUM *backup = NULL;

    // GENERATE RANDOM S-PRIMES
    unsigned char count = 5; // TODO: use less?

    // TODO: random count of primes?
    /*
    if (!RAND_bytes(&count, 1)) {
        printf("Something went wrong! :(\n");
        getchar();


        return EXIT_FAILURE;
    }
    */
        
    BIGNUM *primes[count];

    for (size_t i = 0; i < count; i++) {
        
        primes[i] = BN_new();
        // TODO: use? !(primes[i] = BN_new())
        if (!primes[i]) {
            for (size_t k = 0; k < i; k++) {
                BN_clear_free(primes[k]);    
            }

            perror("BIGNUM allocation failed.\n");
            return EXIT_FAILURE;
        }

        unsigned char sbitCount = 0; // TODO: user more?

        do {
            if (!RAND_bytes(&sbitCount, 1)) {
                for (size_t k = 0; k <= i; k++) {
                    BN_clear_free(primes[k]);
                }

                perror("S-bit count generation failed\n");
                return EXIT_FAILURE;
            }
        } while (sbitCount <= RSA_S_BITS);
                    
        if (!BN_generate_prime_ex(primes[i], sbitCount, 0, NULL, NULL, NULL)) {
            for (size_t k = 0; k <= i; k++) {
                BN_clear_free(primes[k]);
            }
            
            perror("S-prime generation failed\n");
            return EXIT_FAILURE;
        }
    }
    
    // MULTIPLY ALL S-PRIMES
    BIGNUM *const result = BN_dup(BN_value_one());
    if (!result) {
        for (size_t i = 0; i < count; i++) {
            BN_clear_free(primes[i]);
        }   

        perror("BIGNUM allocation failed.\n");
        return EXIT_FAILURE;
    }
    
    for (size_t i = 0; i < count; i++) {
        backup = result;

        if (!BN_mul(result, primes[i], result, ctx)) {
            for (size_t k = 0; k < count; k++) {
                BN_clear_free(primes[k]);
            }
            
            BN_clear_free(backup);

            perror("S-primes multiplication failed.\n");
            return EXIT_FAILURE;
        }            
    }

    backup = NULL;
    for (size_t i = 0; i < count; i++) {
        BN_clear_free(primes[i]);
    }


    // MULTIPLY WITH RANDOM 1 <= a <= L a and 2 and then add 1 
    unsigned char aBuffer[RSA_L_BITS / 8];
    
    if (!RAND_bytes(aBuffer, RSA_L_BITS / 8)) {
        BN_clear_free(result);

        perror("'a' generation failed\n");
        return EXIT_FAILURE;
    }
    
    long a = 0; // TODO: is ok?
    memcpy(&a, aBuffer, RSA_L_BITS / 8);

    backup = result;
    if (!BN_mul_word(result, a * 2)) {
        BN_clear_free(backup);

        perror("result * 2 failed\n");
        return EXIT_FAILURE;
    }
    backup = NULL;

    BIGNUM *resultMinOne = BN_dup(result);
    if (!resultMinOne) {
        BN_clear_free(result);

        perror("BIGNUM allocation failed\n");
        return EXIT_FAILURE;
    }
    
    backup = result;
    if (!BN_add_word(result, 1)) {
        BN_clear_free(backup);
        BN_clear_free(resultMinOne);

        perror("result + 1 failed\n");
        return EXIT_FAILURE;
    }
    backup = NULL;


    // PRIMALITY TEST + PRIME GENERATION
    BIGNUM *const gcdResult = BN_secure_new();
    if (!gcdResult) {
        BN_clear_free(result);
        BN_clear_free(resultMinOne);

        perror("BIGNUM allocation failed\n");
        return EXIT_FAILURE;
    }

    while (true) {
        if (BN_is_prime_ex(result, BN_prime_checks, ctx, NULL) == 1) {
            
            backup = gcdResult;
            if (!BN_gcd(gcdResult, resultMinOne, e, ctx)) { // TODO: GCD vulnerability in OpenSSL
                BN_clear_free(backup);
                BN_clear_free(result);
                BN_clear_free(resultMinOne);

                perror("GCD(result - 1, e) computation failed\n");
                return EXIT_FAILURE;
            }
            backup = NULL;

            
            if (BN_is_one(gcdResult)) {
                BN_clear_free(gcdResult);
                
                char *resultString = BN_bn2dec(result);
                if (!resultString) {
                    perror("Could not print out the generated prime\n");
                    return EXIT_FAILURE;
                }
                
                printf("Found a (2^%d-2^%d)-prime coprime with e: %s\n\n", RSA_L_BITS, RSA_S_BITS, resultString);
                OPENSSL_clear_free(resultString, sizeof(*resultString));

                *safePrime = result;
                *phiSafePrime = resultMinOne;
                OPENSSL_assert(*safePrime);
                OPENSSL_assert(*phiSafePrime);
                return EXIT_SUCCESS;
            }
        }

        backup = result;
        if (!BN_add_word(result, 2)) {
            BN_clear_free(backup);
            BN_clear_free(resultMinOne);

            perror("prime + 2 generation failed\n");
            return EXIT_FAILURE;
        }

        backup = resultMinOne;
        if (!BN_add_word(resultMinOne, 2)) {
            BN_clear_free(backup);
            BN_clear_free(result);

            perror("prime copying failed\n");
            return EXIT_FAILURE;
        }
        backup = NULL;
            
    }
}
