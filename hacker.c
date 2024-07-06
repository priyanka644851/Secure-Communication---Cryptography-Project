#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define PORT 8001
#define SIZE_ETHERNET 14

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

void sendMaliciousMessage(char mal_message[]){
  int sockfd;
    struct sockaddr_in servaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        return;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    int n, len;

	unsigned char key[8] = "23456789";
    unsigned char encrypted_message[1024] = {0};
    encryptDES((unsigned char *)mal_message, key, encrypted_message);

	printf("Encrypted message: ");
    for (int i = 0; i < strlen((char *)encrypted_message); i++)
        printf("%02x", encrypted_message[i]);
    	printf("\n");

    // Calculate hash of encrypted message
    unsigned char hash[SHA_DIGEST_LENGTH];
    calculateHash(mal_message, hash);

    // Send encrypted message to server
    sendto(sockfd, encrypted_message, strlen((char *)encrypted_message), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // Send hash to server
    sendto(sockfd, hash, SHA_DIGEST_LENGTH, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
	printf("Hash sent to server: ");
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    	printf("\n");       

    close(sockfd);
    return;   
}
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    const u_char *payload;
    int payload_len;

    // Ethernet header is 14 bytes, IP header is 20 bytes, UDP header is 8 bytes
    payload = packet + SIZE_ETHERNET + 20 + 8; // Adjust the offset to skip headers
    payload_len = header->len - (SIZE_ETHERNET + 20 + 8); // Calculate payload length
    
	printf("Intercepted message : ");
    for (int i = 0; i < payload_len; i++)
        printf("%02x", payload[i]);
    	printf("\n");

 	char mal_message[100];
    printf("Enter the malicious message : ");
	fgets(mal_message,sizeof(mal_message),stdin);
	if(mal_message[0]=='#') return;
	
    sendMaliciousMessage(mal_message);

}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open a live capture handle
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 2;
    }

    // Set a filter to capture only TCP traffic on specified port
    struct bpf_program fp;
    char filter_exp[] = "port 8080";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    // Start packet capture loop
    pcap_loop(handle, -1, packet_handler, NULL);

    // Close the handle
    pcap_close(handle);
    
    return 0;
}
