// PacketSniffer++ - Extended Version with TCP/UDP Header Parsing
// OS: Linux | Language: C++

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <ctime>

void ProcessPacket(unsigned char* , int);
void PrintIPHeader(unsigned char* , int);
void PrintTCPHeader(unsigned char* , int);
void PrintUDPHeader(unsigned char* , int);
void PrintData(unsigned char* , int);

int main() {
    int sock_raw;
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    unsigned char *buffer = new unsigned char[65536];

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    std::cout << "\n[+] Starting Packet Capture... Press Ctrl+C to stop." << std::endl;

    while (true) {
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_len);
        if (data_size < 0) {
            perror("Recvfrom error");
            return 1;
        }
        ProcessPacket(buffer, data_size);
    }

    close(sock_raw);
    delete[] buffer;
    return 0;
}

void ProcessPacket(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) {
        case 1:
            std::cout << "\n[ICMP Packet]" << std::endl;
            PrintIPHeader(buffer, size);
            break;
        case 6:
            std::cout << "\n[TCP Packet]" << std::endl;
            PrintIPHeader(buffer, size);
            PrintTCPHeader(buffer, size);
            break;
        case 17:
            std::cout << "\n[UDP Packet]" << std::endl;
            PrintIPHeader(buffer, size);
            PrintUDPHeader(buffer, size);
            break;
        default:
            break;
    }
}

void PrintIPHeader(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;

    std::cout << "IP Header Info:" << std::endl;
    std::cout << " |-Source IP        : " << inet_ntoa(source.sin_addr) << std::endl;
    std::cout << " |-Destination IP   : " << inet_ntoa(dest.sin_addr) << std::endl;
    std::cout << " |-Protocol         : " << (unsigned int)iph->protocol << std::endl;
}

void PrintTCPHeader(unsigned char* buffer, int size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

    std::cout << "TCP Header Info:" << std::endl;
    std::cout << " |-Source Port      : " << ntohs(tcph->source) << std::endl;
    std::cout << " |-Destination Port : " << ntohs(tcph->dest) << std::endl;
    std::cout << " |-Sequence Number  : " << ntohl(tcph->seq) << std::endl;
    std::cout << " |-Ack Number       : " << ntohl(tcph->ack_seq) << std::endl;
    std::cout << " |-Header Length    : " << (unsigned int)tcph->doff * 4 << " Bytes" << std::endl;
}

void PrintUDPHeader(unsigned char* buffer, int size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

    std::cout << "UDP Header Info:" << std::endl;
    std::cout << " |-Source Port      : " << ntohs(udph->source) << std::endl;
    std::cout << " |-Destination Port : " << ntohs(udph->dest) << std::endl;
    std::cout << " |-UDP Length       : " << ntohs(udph->len) << std::endl;
}
