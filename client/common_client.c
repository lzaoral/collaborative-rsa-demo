#include <stdbool.h>
#include <openssl/bn.h>

#include "common_client.h"

int generateRSAKeys()
{

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();

    int result = 0;

    result = generateLSSafePrime(p);
    result = result && generateLSSafePrime(q);

    if (!result)
    {
        // handle error

        return EXIT_FAILURE;
    }

    printf("Key generated!\n");

    return EXIT_SUCCESS;
}

int generateLSSafePrime(BIGNUM *safePrime)
{
    bool isSafe = false;

    printf("Su tu\n");

    while (!isSafe)
    {
        printf("Su vnu\n");

        if (BN_generate_prime_ex(safePrime, 2048, 0, NULL, NULL, NULL) == 0)
        {
            printf("neco se posralo\n");

            // TODO: Handle error
            return EXIT_FAILURE;
        }

        char *string = BN_bn2dec(safePrime);
        printf("Cislo: %s\n", string);
    }

    return EXIT_SUCCESS;
}
