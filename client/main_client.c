#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "common_client.h"

int main() {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	const char *menuMsg = "Choose action:\n"
	                      "1. Generate and store keys\n"
	                      "2. Test implementation\n"
	                      "0. Exit program\n"
	                      "Selection:\n";

	BIGNUM *e = NULL;
	BIGNUM *d = NULL;
	BIGNUM *n = NULL;

	while (true) {
		printf("%s", menuMsg);

		int input = 0;
		scanf("%d", &input);

		switch (input) {

		case 0:
			printf("Exit...\n");

			EVP_cleanup();
			CRYPTO_cleanup_all_ex_data();
			ERR_free_strings();

			return EXIT_SUCCESS;
		case 1:
			printf("Generating keys...\n\n");

			if (generateRSAKeys(&e, &d, &n)) {
				return EXIT_FAILURE;
			}

			// TODO: do this somewhere else
			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(n);

			break;

		case 2:
			printf("Running tests...\n\n");

			if (runTest()) {
				fprintf(stderr, "Tests failed!\n");

				return EXIT_FAILURE;
			}

			printf("TESTS OK\n\n");

			break;

		default:
			printf("Unknown choice\n\n");
		}
	}
}
