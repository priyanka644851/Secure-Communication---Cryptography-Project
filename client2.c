#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define PORT 8001
#define MAXLINE 1024
void encryptDES(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext) {
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key, 8);
    DES_set_key(&des_key, &schedule);
    DES_ecb_encrypt((DES_cblock *)plaintext, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
}

void calculateHash(unsigned char *input, unsigned char *hash) {
    SHA1(input, strlen((char *)input), hash);
}


int main() {
    int sockfd;
    unsigned char buffer[MAXLINE];
    char *message = "Hello";
    struct sockaddr_in servaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    int n, len;

    // Encryption part
    unsigned char key[8] = "12345678";
    unsigned char encrypted_message[MAXLINE] = {0};
    encryptDES((unsigned char *)message, key, encrypted_message);

    // Print the encrypted message
    printf("Encrypted message: ");
    for (int i = 0; i < strlen((char *)encrypted_message); i++)
        printf("%02x", encrypted_message[i]);
    	printf("\n");

    // Calculate hash of encrypted message
    unsigned char hash[SHA_DIGEST_LENGTH];
    calculateHash(message, hash);

    // Send encrypted message to server
    sendto(sockfd, encrypted_message, strlen((char *)encrypted_message), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // Send hash to server
    sendto(sockfd, hash, SHA_DIGEST_LENGTH, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // Print the hash sent to the server
    printf("Hash sent to server: ");
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    	printf("\n");

    close(sockfd);
    return 0;
}
