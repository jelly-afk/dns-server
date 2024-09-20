#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct {
    uint16_t ID;
    uint16_t FLAGS;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSOCUNT;
    uint16_t ARCOUNT;
} __attribute__((packed)) dns_header;

typedef struct {
    unsigned char* name;
    uint16_t type;
    uint16_t class;
}  __attribute__((packed)) dns_question;

typedef struct {
    unsigned char* name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rd_length;
    unsigned char* data;
}  __attribute__((packed)) dns_answer;



void pack_response (unsigned char* buffer, dns_header *header, dns_question *question, dns_answer *answer);
int main() {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
    printf("Logs from your program will appear here!\n");

    // Uncomment this block to pass the first stage
 int udpSocket, client_addr_len;
	struct sockaddr_in clientAddress;
	
	udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udpSocket == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}
	
	// Since the tester restarts your program quite often, setting REUSE_PORT
//	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
		printf("SO_REUSEPORT failed: %s \n", strerror(errno));
		return 1;
	}
	
	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(2053),
									 .sin_addr = { htonl(INADDR_ANY) },
									};
	
	if (bind(udpSocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}

   int bytesRead;
   char buffer[512];
   socklen_t clientAddrLen = sizeof(clientAddress);
   
   while (1) {
       // Receive data
       bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientAddrLen);
       if (bytesRead == -1) {
           perror("Error receiving data");
           break;
       }
   
       buffer[bytesRead] = '\0';
       printf("Received %d bytes: %s\n", bytesRead, buffer);
   
       // Create an empty response
        dns_header header = {0};
        dns_question question;
        dns_answer answer;
        header.ID = htons(1234);
        header.FLAGS |= (1 << 7);
        header.QDCOUNT = htons(1);
        header.ANCOUNT = htons(1);
        unsigned char name[] = { 0x0C,
            'c', 'o', 'd', 'e', 'c', 'r', 'a', 'f', 't', 'e', 'r', 's',
            0x02,  
            'i', 'o', 0x00 
        };
        question.name = name;
        question.type = htons(1);
        question.class = htons(1);
        answer.name = name;
        answer.type = htons(1);
        answer.class = htons(1);
        answer.ttl = htonl(69);
        answer.rd_length = htons(4);
        unsigned char ip[] = { 0x08, 0x08, 0x08, 0x08 };
        answer.data = ip;

        
        unsigned char response[512] = {0};

        pack_response(response,  &header, &question, &answer);

        int q_size = strlen((char*)question.name) + 1 + sizeof(question.type) + sizeof(question.class);
        int a_size = strlen((char*)answer.name) + 1 + sizeof(answer.type) + sizeof(answer.class) + sizeof(answer.ttl) + sizeof(answer.rd_length) + sizeof(answer.data);

        int packet_size = sizeof(dns_header) + q_size + a_size;
        printf("size: %d\n", packet_size);
        if (sendto(udpSocket, &response,packet_size, 0, (struct sockaddr*)&clientAddress, sizeof(clientAddress)) == -1) {
            perror("Failed to send response");
        }
    }

   close(udpSocket);

    return 0;
}


void pack_response (unsigned char* buffer, dns_header *header, dns_question *question, dns_answer *answer){
    int x = 0;
    memcpy(buffer, header, sizeof(dns_header));
    x += sizeof(dns_header);
    int name_len = strlen((char*)question->name)+1;
    memcpy(buffer+x, question->name, name_len);
    x += name_len;
    memcpy(buffer+x, &question->class, sizeof(uint16_t));
    x += sizeof(uint16_t);
    memcpy(buffer+x, &question->type, sizeof(uint16_t));
    x += sizeof(uint16_t);

    name_len = strlen((char*)answer->name)+1;
    memcpy(buffer+x, answer->name,  name_len);
    x+= name_len;

    memcpy(buffer+x, &answer->type, sizeof(uint16_t));
    x += sizeof(uint16_t);

    memcpy(buffer+x, &answer->class,  sizeof(uint16_t));
    x += sizeof(uint16_t);

    memcpy(buffer+x, &answer->ttl, sizeof(uint32_t));
    x += sizeof(uint32_t);

    memcpy(buffer+x, &answer->rd_length, sizeof(uint16_t));
    x += sizeof(uint16_t);

    memcpy(buffer+x, &answer->data, ntohs(answer->rd_length));
    x += ntohs(answer->rd_length);   
}











