#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MD5_BLOCK_SIZE 64
#define MD5_HASH_SIZE 4

int i, grp, q, p;

// Rotate left operation (circular shift)
unsigned rotate_left(unsigned x, short n) {
    return (x << n) | (x >> (32 - n));
}

// MD5 auxiliary functions
unsigned func0(unsigned abcd[]) { return (abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]); }
unsigned func1(unsigned abcd[]) { return (abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]); }
unsigned func2(unsigned abcd[]) { return abcd[1] ^ abcd[2] ^ abcd[3]; }
unsigned func3(unsigned abcd[]) { return abcd[2] ^ (abcd[1] | ~abcd[3]); }

typedef unsigned (*HashFunction)(unsigned a[]);

// Function to create MD5 constant table
unsigned* create_md5_table(unsigned *k) {
    double pwr = pow(2, 32);
    for (i = 0; i < 64; i++) {
        k[i] = (unsigned)(fabs(sin(1 + i)) * pwr);
    }
    return k;
}

// MD5 Algorithm implementation
unsigned* md5(const char *msg, int mlen) {
    static unsigned h[MD5_HASH_SIZE] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    static HashFunction ff[] = {&func0, &func1, &func2, &func3};
    static unsigned kspace[64];
    static unsigned *k = NULL;

    if (k == NULL) {
        k = create_md5_table(kspace);
    }

    unsigned abcd[4] = {0};

    // Initialize hash values
    memcpy(abcd, h, sizeof(abcd));

    // Prepare the message with padding
    int padded_len = mlen + 64 - (mlen % 64);  // Ensure the length is a multiple of 64
    unsigned char *msg2 = (unsigned char *)malloc(padded_len);
    memcpy(msg2, msg, mlen);
    msg2[mlen] = 0x80;  // Append a 1 bit followed by 0 bits
    memset(msg2 + mlen + 1, 0, padded_len - mlen - 9);

    // Add the original message length in bits
    unsigned long long bit_len = mlen * 8;
    memcpy(msg2 + padded_len - 8, &bit_len, 8);

    // Process the message in 512-bit (64-byte) blocks
    for (grp = 0; grp < padded_len / 64; grp++) {
        unsigned char *block = msg2 + grp * 64;
        memcpy(abcd, h, sizeof(abcd));

        // Process each of the 16 words in the block
        for (p = 0; p < 4; p++) {
            HashFunction fctn = ff[p];
            for (q = 0; q < 16; q++) {
                unsigned f = abcd[1] + rotate_left(abcd[0] + fctn(abcd) + k[q + 16 * p] + block[q * 4], 7);
                abcd[0] = abcd[3];
                abcd[3] = abcd[2];
                abcd[2] = abcd[1];
                abcd[1] = f;
            }
        }

        // Update the hash values
        for (p = 0; p < 4; p++) {
            h[p] += abcd[p];
        }
    }

    free(msg2);  // Free the allocated memory for the padded message
    return h;
}

int main() {
    const char *msg = "The quick brown fox jumps over the lazy dog";
    unsigned* d = md5(msg, strlen(msg));

    // Print the MD5 hash
    printf("MD5 Encryption Algorithm\n\n");
    printf("Input String: %s\n", msg);
    printf("MD5 Hash: ");
    for (i = 0; i < MD5_HASH_SIZE; i++) {
        printf("%08x", d[i]);
    }
    printf("\nMD5 Encryption Completed Successfully!\n");

    return 0;
}
