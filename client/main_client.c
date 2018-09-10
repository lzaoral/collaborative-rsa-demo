#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "common_client.h"

int main()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    while (true)
    {
        int input = 0;

        printf("Choose 1:\n");
        scanf("%d", &input);

        switch (input)
        {
        case 0:
            printf("Exit...\n");

            EVP_cleanup();
            CRYPTO_cleanup_all_ex_data();
            ERR_free_strings();

            return EXIT_SUCCESS;
        case 1:

            printf("Generating keys...\n");

            if (generateRSAKeys())
            {
                return EXIT_FAILURE;
            }

            break;
        default:
            printf("Unknown choice\n");
            return EXIT_FAILURE;
        }
    }
}
