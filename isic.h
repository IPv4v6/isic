#include <strings.h>

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif

#include <libnet.h>

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>

#ifndef ETHER_FRAME_SIZE
#define ETHER_FRAME_SIZE 1500
#endif

#define IP_H      20
#define UDP_H     8
#define IP6_H     40
#define IP6_FRAGH 8
#define ICMP6_H   8

/* We want a random function that returns 0 to 0x7fff */
#if ( RAND_MAX != 2147483647 )  /* expect signed long */
#error Random IP generation broken: unexpected RAND_MAX.
#endif

#define RAND8  ((u_int8_t)(rand() & 0xff))
#define RAND16 ((u_int16_t)(rand() & 0xffff))
#define RAND32 ((u_int32_t)((RAND16 << 16) + RAND16))

void usage(char *);
void sighandler(int);
