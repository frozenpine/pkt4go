#pragma once
#ifndef TCPIP_HEADERS_H
#define TCPIP_HEADERS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef _WIN32
#define VOID void
#endif

#define ETHER_HEADER_LEN 14
#define LOOPBACK_HEADER_LEN 4

int link_type;
bool is_offline;

#define ETHER_ADDR_LEN 6
#define PROTO_IP 0x0800
#define PROTO_ARP 0x0806
#define PROTO_TCP 0x06
#define PROTO_UDP 0x11

/* Ethernet header */
typedef struct EtherHeader
{
	uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	uint16_t ether_type;				 /* IP? ARP? RARP? etc */
} EtherHeader;

/* 4 bytes IP address */
typedef struct IPAddress
{
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;
	uint8_t byte4;
} IPAddress;

/* IPv4 header */
typedef struct IPHeader
{
	uint8_t ver_ihl; // Version (4 bits) + Internet header length (4 bits)
#define IH_OFF(ih) (((ih)->ver_ihl & 0xf) * 4)
	uint8_t tos;			 // Type of service
	uint16_t tlen;			 // Total length
	uint16_t identification; // Identification
	uint16_t flags_fo;		 // Flags (3 bits) + Fragment offset (13 bits)
	uint8_t ttl;			 // Time to live
	uint8_t proto;			 // Protocol
	uint16_t crc;			 // Header checksum
	IPAddress saddr;		 // Source address
	IPAddress daddr;		 // Destination address
	uint32_t op_pad;		 // Option + Padding
} IPHeader;

/* TCP header */
typedef uint32_t tcp_seq;

typedef struct TCPHeader
{
	uint16_t sport;	  /* source port */
	uint16_t dport;	  /* destination port */
	tcp_seq seq;	  /* sequence number */
	tcp_seq ack;	  /* acknowledgement number */
	uint8_t th_offx2; /* data offset, rsvd */
#define TH_OFF(th) ((((th)->th_offx2 & 0xf0) >> 4) * 4)
	uint8_t flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
	uint16_t win; /* window */
	uint16_t sum; /* checksum */
	uint16_t urp; /* urgent pointer */
} TCPHeader;

/* UDP header*/
typedef struct UDPHeader
{
	uint16_t sport; // Source port
	uint16_t dport; // Destination port
	uint16_t len;	// Datagram length
	uint16_t crc;	// Checksum
} UDPHeader;

#define TH_SYN_ACK (TH_SYN | TH_ACK)
#define TH_FIN_ACK (TH_FIN | TH_FIN)

#endif