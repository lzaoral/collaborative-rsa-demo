#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <string.h>

#include "common_client.h"

int generateRSAKeys(BIGNUM **e, BIGNUM **d, BIGNUM **n) {

	// INITIALIZATION PHASE
	BIGNUM *backup = NULL;
	char *printString = NULL;

	BN_CTX *const ctx = BN_CTX_secure_new();
	if (!ctx) {
		fprintf(stderr, "BIGNUM CTX allocation failed.\n");
		return EXIT_FAILURE;
	}

	*e = BN_secure_new();
	if (!*e) {
		BN_CTX_free(ctx);

		fprintf(stderr, "BIGNUM allocation failed.\n");
		return EXIT_FAILURE;
	}

	if (!BN_set_word(*e, RSA_PUBLIC_KEY)) {
		BN_clear_free(*e);
		BN_CTX_free(ctx);

		fprintf(stderr, "Conversion of public key to BIGNUM failed\n");
		return EXIT_FAILURE;
	}

	// PRIMES GENERATION
	BIGNUM *p = NULL;
	BIGNUM *q = NULL;
	BIGNUM *phiP = NULL;
	BIGNUM *phiQ = NULL;

	printf("Generating p...\n");
	if (generateLSSafePrime(*e, &p, &phiP, ctx)) {
		BN_clear_free(*e);
		BN_CTX_free(ctx);

		fprintf(stderr, "Could not generate p! :(\n");
		return EXIT_FAILURE;
	}

	printf("Generating q...\n");
	if (generateLSSafePrime(*e, &q, &phiQ, ctx)) {
		BN_clear_free(*e);
		BN_clear_free(p);
		BN_clear_free(phiP);
		BN_CTX_free(ctx);

		fprintf(stderr, "Could not generate q! :(\n");
		return EXIT_FAILURE;
	}

	printf("(2^%d-2^%d)-safe primes generated!\n\n", RSA_L_BITS, RSA_S_BITS);

	// PUBLIC MODULUS GENERATION
	*n = BN_secure_new();

	if (!*n) {
		BN_clear_free(*e);
		BN_clear_free(p);
		BN_clear_free(q);
		BN_clear_free(phiP);
		BN_clear_free(phiQ);

		BN_CTX_free(ctx);

		fprintf(stderr, "BIGNUM allocation failed.\n");
		return EXIT_FAILURE;
	}

	backup = *n;
	if (!BN_mul(*n, p, q, ctx)) {
		BN_clear_free(backup);
		BN_clear_free(*e);
		BN_clear_free(p);
		BN_clear_free(q);
		BN_clear_free(phiP);
		BN_clear_free(phiQ);

		BN_CTX_free(ctx);

		fprintf(stderr, "Could not compute the public modulus.\n");
		return EXIT_FAILURE;
	}
	backup = NULL;

	printString = BN_bn2dec(*n);
	if (!printString) {
		BN_clear_free(*n);
		BN_clear_free(*e);
		BN_clear_free(p);
		BN_clear_free(q);
		BN_clear_free(phiP);
		BN_clear_free(phiQ);

		BN_CTX_free(ctx);

		fprintf(stderr, "Could not print out the public modulus.\n");
		return EXIT_FAILURE;
	}

	printf("Public modulus: %s\n\n", printString);
	OPENSSL_clear_free(printString, sizeof(*printString));
	printString = NULL;

	// PRIVATE KEY GENERATION
	BIGNUM *phiN = BN_secure_new();
	if (!phiN) {
		BN_clear_free(*n);
		BN_clear_free(*e);
		BN_clear_free(p);
		BN_clear_free(q);
		BN_clear_free(phiP);
		BN_clear_free(phiQ);

		BN_CTX_free(ctx);

		fprintf(stderr, "BIGNUM allocation failed.\n");
		return EXIT_FAILURE;
	}

	backup = phiN;
	if (!BN_mul(phiN, phiP, phiQ, ctx)) {
		BN_clear_free(backup);
		BN_clear_free(*n);
		BN_clear_free(*e);
		BN_clear_free(p);
		BN_clear_free(q);
		BN_clear_free(phiP);
		BN_clear_free(phiQ);

		BN_CTX_free(ctx);

		fprintf(stderr, "Could not compute phi of the public modulus.\n");
		return EXIT_FAILURE;
	}
	backup = NULL;

	BN_clear_free(phiP);
	BN_clear_free(phiQ);
	phiP = NULL;
	phiQ = NULL;

	*d = BN_secure_new();
	if (!*d) {
		BN_clear_free(*n);
		BN_clear_free(*e);
		BN_clear_free(p);
		BN_clear_free(q);
		BN_clear_free(phiN);

		BN_CTX_free(ctx);

		fprintf(stderr, "BIGNUM allocation failed.\n");
		return EXIT_FAILURE;
	}

	backup = *d;
	if (!BN_mod_inverse(*d, *e, phiN, ctx)) {
		BN_clear_free(backup);
		BN_clear_free(*n);
		BN_clear_free(*e);
		BN_clear_free(p);
		BN_clear_free(q);
		BN_clear_free(phiN);

		BN_CTX_free(ctx);

		fprintf(stderr, "Private key computation failed.\n");
		return EXIT_FAILURE;
	}
	backup = NULL;

	printString = BN_bn2dec(*d);
	if (!printString) {
		BN_clear_free(*d);
		BN_clear_free(*n);
		BN_clear_free(*e);
		BN_clear_free(p);
		BN_clear_free(q);
		BN_clear_free(phiN);

		BN_CTX_free(ctx);

		fprintf(stderr, "Could not print out the private key.\n");
		return EXIT_FAILURE;
	}

	printf("Private key: %s\n\n", printString);
	OPENSSL_clear_free(printString, sizeof(*printString)); // TODO: probably not ok, right?
	printString = NULL;

	// CLEANUP
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(phiN);

	BN_CTX_free(ctx);

	return EXIT_SUCCESS;
}

int generateLSSafePrime(BIGNUM const *const e, BIGNUM **const safePrime, BIGNUM **const phiSafePrime, BN_CTX *const ctx) {

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

			fprintf(stderr, "BIGNUM allocation failed.\n");
			return EXIT_FAILURE;
		}

		unsigned char sbitCount = 0; // TODO: use more?

		do {
			if (!RAND_bytes(&sbitCount, 1)) {
				for (size_t k = 0; k <= i; k++) {
					BN_clear_free(primes[k]);
				}

				fprintf(stderr, "S-bit count generation failed\n");
				return EXIT_FAILURE;
			}
		} while (sbitCount <= RSA_S_BITS);

		if (!BN_generate_prime_ex(primes[i], sbitCount, 0, NULL, NULL, NULL)) {
			for (size_t k = 0; k <= i; k++) {
				BN_clear_free(primes[k]);
			}

			fprintf(stderr, "S-prime generation failed\n");
			return EXIT_FAILURE;
		}
	}

	// MULTIPLY ALL S-PRIMES
	BIGNUM *const result = BN_dup(BN_value_one());
	if (!result) {
		for (size_t i = 0; i < count; i++) {
			BN_clear_free(primes[i]);
		}

		fprintf(stderr, "BIGNUM allocation failed.\n");
		return EXIT_FAILURE;
	}

	for (size_t i = 0; i < count; i++) {
		backup = result;

		if (!BN_mul(result, primes[i], result, ctx)) {
			for (size_t k = 0; k < count; k++) {
				BN_clear_free(primes[k]);
			}

			BN_clear_free(backup);

			fprintf(stderr, "S-primes multiplication failed.\n");
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

		fprintf(stderr, "'a' generation failed\n");
		return EXIT_FAILURE;
	}

	long a = 0; // TODO: is ok?
	memcpy(&a, aBuffer, RSA_L_BITS / 8);

	backup = result;
	if (!BN_mul_word(result, a * 2)) {
		BN_clear_free(backup);

		fprintf(stderr, "result * 2 failed\n");
		return EXIT_FAILURE;
	}
	backup = NULL;

	BIGNUM *resultMinOne = BN_dup(result);
	if (!resultMinOne) {
		BN_clear_free(result);

		fprintf(stderr, "BIGNUM allocation failed\n");
		return EXIT_FAILURE;
	}

	backup = result;
	if (!BN_add_word(result, 1)) {
		BN_clear_free(backup);
		BN_clear_free(resultMinOne);

		fprintf(stderr, "result + 1 failed\n");
		return EXIT_FAILURE;
	}
	backup = NULL;

	// PRIMALITY TEST + PRIME GENERATION
	BIGNUM *const gcdResult = BN_secure_new();
	if (!gcdResult) {
		BN_clear_free(result);
		BN_clear_free(resultMinOne);

		fprintf(stderr, "BIGNUM allocation failed\n");
		return EXIT_FAILURE;
	}

	while (true) {
		if (BN_is_prime_ex(result, BN_prime_checks, ctx, NULL) == 1) {

			backup = gcdResult;
			if (!BN_gcd(gcdResult, resultMinOne, e, ctx)) { // TODO: GCD vulnerability in OpenSSL
				BN_clear_free(backup);
				BN_clear_free(result);
				BN_clear_free(resultMinOne);

				fprintf(stderr, "GCD(result - 1, e) computation failed\n");
				return EXIT_FAILURE;
			}
			backup = NULL;

			if (BN_is_one(gcdResult)) {
				BN_clear_free(gcdResult);

				char *resultString = BN_bn2dec(result);
				if (!resultString) {
					fprintf(stderr, "Could not print out the generated prime\n");
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

			fprintf(stderr, "prime + 2 generation failed\n");
			return EXIT_FAILURE;
		}

		backup = resultMinOne;
		if (!BN_add_word(resultMinOne, 2)) {
			BN_clear_free(backup);
			BN_clear_free(result);

			fprintf(stderr, "prime copying failed\n");
			return EXIT_FAILURE;
		}
		backup = NULL;
	}
}

int runTest() {
	const char *const testMsgStr = "48654681406840615136541141350146514654630436044654674266181";
	BIGNUM *testMsg = NULL;
	BIGNUM *backup = NULL;

	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;

	BN_CTX *const ctx = BN_CTX_secure_new();

	if (!ctx) {
		fprintf(stderr, "BIGNUM CTX allocation failed.\n");

		return EXIT_FAILURE;
	}

	if (!BN_dec2bn(&testMsg, testMsgStr)) {
		fprintf(stderr, "Test message BIGNUM allocation failed.\n");

		BN_CTX_free(ctx);

		return EXIT_FAILURE;
	}

	for (size_t i = 1; i <= 1; i++) {
		generateRSAKeys(&e, &d, &n);

		BIGNUM *ciphertext = BN_secure_new();
		if (!ciphertext) {
			fprintf(stderr, "BIGNUM allocation failed.\n");

			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(n);
			BN_clear_free(testMsg);
			BN_CTX_free(ctx);

			return EXIT_FAILURE;
		}

		backup = ciphertext;
		if (!BN_mod_exp(ciphertext, testMsg, e, n, ctx)) {
			fprintf(stderr, "Encrypting failed.\n");

			BN_clear_free(backup);
			BN_clear_free(testMsg);
			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(n);
			BN_CTX_free(ctx);

			return EXIT_FAILURE;
		}
		backup = NULL;

		BIGNUM *result = BN_secure_new();
		if (!result) {
			fprintf(stderr, "BIGNUM allocation failed.\n");

			BN_clear_free(ciphertext);
			BN_clear_free(testMsg);
			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(n);
			BN_CTX_free(ctx);

			return EXIT_FAILURE;
		}

		backup = result;
		if (!BN_mod_exp(result, ciphertext, d, n, ctx)) {
			fprintf(stderr, "Decrypting failed.\n");

			BN_clear_free(backup);
			BN_clear_free(ciphertext);
			BN_clear_free(testMsg);
			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(n);
			BN_CTX_free(ctx);

			return EXIT_FAILURE;
		}
		backup = NULL;

		if (BN_cmp(result, testMsg) != 0) {
			fprintf(stderr, "\nTEST no%ld: NOK\n\n", i);

			BN_clear_free(result);
			BN_clear_free(ciphertext);
			BN_clear_free(testMsg);
			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(n);
			BN_CTX_free(ctx);

			return EXIT_FAILURE;
		}

		printf("\nTEST no%ld: OK\n\n", i);

		BN_clear_free(result);
		BN_clear_free(ciphertext);
		BN_clear_free(testMsg);
		BN_clear_free(e);
		BN_clear_free(d);
		BN_clear_free(n);
		BN_CTX_free(ctx);
	}

	return EXIT_SUCCESS;
}
