#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#define PACKET_BUFFER_SIZE 65536

int process_packet(unsigned char *, int);

int main() {
    int rawSocket;
    struct sockaddr server;
    socklen_t server_len = sizeof(server);
    unsigned char packet_buffer[PACKET_BUFFER_SIZE];

    // Creating a raw socket 
    rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rawSocket == -1) {
        perror("Error in creating socket");
        exit(1);
    }

    // Receiving packets
    while (1) {
        int packet_size = recvfrom(rawSocket, packet_buffer, PACKET_BUFFER_SIZE, 0, &server, &server_len);
        if (packet_size == -1) {
            perror("Error in receiving packet");
            close(rawSocket);
            exit(1);
        }
	
        if (process_packet(packet_buffer, packet_size)) break;
    }

    close(rawSocket);
    return 0;
}

int process_packet(unsigned char *packet, int packet_size) {
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    // Converting IP addresses to human-readable format
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
    
    packet[packet_size]='\0';
    char *payload = packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    if (strstr(payload, "Flag") != NULL) {
    	if (strstr(payload,"skip this packet") != NULL) return 0;
        printf("Found 'Flag' keyword in packet payload:\n");
        printf("Source IP: %s\n", src_ip);
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination IP: %s\n", dest_ip);
        printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
        printf("Payload Data:\n");

        for (int i = 0; i < strlen(payload); i++) {
            if (payload[i] >= 32 && payload[i] <= 126) {
                putchar(payload[i]);
            } else {
                putchar('.');
            }
        }
        printf("\n");
        return 1;
    }
    return 0;
}