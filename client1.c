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

void decryptDES(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext) {
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key, 8);
    DES_set_key(&des_key, &schedule);
    DES_ecb_encrypt((DES_cblock *)ciphertext, (DES_cblock *)plaintext, &schedule, DES_DECRYPT);
}

void calculateHash(unsigned char *input, unsigned char *hash) {
    SHA1(input, strlen((char *)input), hash);
}

int main() {
    int sockfd;
    unsigned char buffer[MAXLINE];
    struct sockaddr_in servaddr, cliaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    int len, n;
    len = sizeof(cliaddr); //len is value/result

    // Receive message from client
    while (1) 
	{
        memset(buffer, 0, sizeof(buffer));
        
        //Receiving encrypted message from sender
        n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
        buffer[n] = '\0';
		printf("Message received from client : ");
	    for (int i = 0; i < strlen((char *)buffer); i++)
	        printf("%02x", buffer[i]);
	    	printf("\n");

        // Receive hash from client
        unsigned char received_hash[SHA_DIGEST_LENGTH];
        recvfrom(sockfd, received_hash, SHA_DIGEST_LENGTH, 0, (struct sockaddr *)&cliaddr, &len);
		printf("Received hash : ");
	    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
	        printf("%02x", received_hash[i]);
	    	printf("\n");
	    	
    
    	//Decrypting using symmetric key
    	unsigned char key[8] = "12345678";
    	unsigned char decrypted_message[MAXLINE] = {0};
    	decryptDES(buffer, key, decrypted_message);
    	
    	
        // Calculate hash of received message
        unsigned char hash[SHA_DIGEST_LENGTH];
        calculateHash(decrypted_message, hash);
		printf("Calculated hash : ");
		for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        	printf("%02x", hash[i]);
    		printf("\n");
    		
        // Compare received hash with calculated hash
        if (memcmp(hash, received_hash, SHA_DIGEST_LENGTH) == 0) {
            printf("Hashes match.\n");
            // Print decrypted message
            printf("Decrypted message: %s\n", decrypted_message);
        } else {
            printf("Hashes do not match. Message may have been tampered with.\n");
        }
    }

    close(sockfd);
    return 0;
}
