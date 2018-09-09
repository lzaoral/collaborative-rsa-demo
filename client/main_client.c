#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common_client.h"

int main()
{

    while (true)
    {
        int input = 0;

        scanf("%d", &input);

        switch (input)
        {
        case 0:
            printf("Exit...");
            return EXIT_SUCCESS;
        case 1:

            printf("Generate keys");

            if (generateRSAKeys())
            {
                return EXIT_FAILURE;
            }

            break;
        default:
            printf("Unknown choice");
            return EXIT_FAILURE;
        }
    }
}
