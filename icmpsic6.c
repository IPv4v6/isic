#include "isic.h"

/* This is tuned for ethernet sized frames (1500 bytes)
 * For user over a modem or frame (or other) you will have to change the
 * 'rand() & 0x4ff' line below.  The 0x4ff needs to be less than the size of
 * the frame size minus the length of the ip header (20 bytes IIRC) minus the
 * length of the TCP header.
 */


/* Variables shared between main and the signal handler so we can display
 * output if ctrl-c'd
 */
u_int seed = 0;
u_long acx = 0;
struct timeval starttime;
u_long datapushed = 0;			/* How many bytes we pushed */


int
main(int argc, char **argv)
{
	int c,  frag_flag = 0, dstopt_flag = 0;
	u_char *buf = NULL;
	u_short	*payload = NULL;
	u_int payload_s = 0;
	int packet_len = 0, dstopt_tlen = 0;
	char addrbuf[INET6_ADDRSTRLEN];

	/* libnet variables */
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *l;
	char *device = NULL;

	/* Packet Variables */
	u_int src_addr_flag = 0, dst_addr_flag = 0;
	struct ip6_hdr *ip6 = NULL;
	u_char ver, hlim, nxt;
	u_int16_t plen;
	u_int32_t flow;	
	struct libnet_in6_addr src_addr;
	struct libnet_in6_addr dst_addr;

	struct icmp6_hdr *icmp6 = NULL;

	struct ip6_frag *ip6_fraghdr = NULL; /* IPv6 fragment header */
	u_char f6_nxt = 0, f6_rsv = 0;
	u_int32_t f6_id = 0;
	u_int16_t f6_offlg = 0;

	struct ip6_dest *ip6_dopthdr = NULL; /* IPv6 destination option header */
	u_char dstopt_nxt = 0, dstopt_len = 0;

	/* Functionality Variables */
	int src_ip_rand = 0, dst_ip_rand = 0;
	struct timeval tv, tv2;
	float sec;
	unsigned int cx = 0;
	u_long max_pushed = 10240;		/* 10MB/sec */
	u_long num_to_send = 0xffffffff;	/* Send 4billion packets */
	u_long skip = 0; 			/* Skip how many packets */
	int printout = 0;			/* Debugging */
	u_int repeat = 1;

	/* Defaults */
	float FragPct	=	10;
	float DstOpts	=	10;
	float ICMPCksm	=	10;



	/* Not crypto strong randomness but we don't really care.  And this  *
	 * gives us a way to determine the seed while the program is running *
 	 * if we need to repeat the results				     */
	seed = getpid();

	/* Initialize libnet context, Root priviledges are required.*/ 
	l = libnet_init(
            LIBNET_RAW6_ADV,                        /* injection type */
            device,                                 /* network interface */
            errbuf);                                /* error buffer */

	if (l == NULL) {
	  fprintf(stderr, "libnet_init() failed: %s", errbuf);
	  exit( -1 );
	}

	while((c = getopt(argc, argv, "hd:s:r:m:k:Dp:F:I:i:vx:")) != EOF) {
	  switch (c) {
	   case 'h':
		usage(argv[0]);
		exit(0);
		break;
	   case 'd':
		if ( strcmp(optarg, "rand") == 0 ) {
			printf("Using random dest IP's\n");
			dst_addr_flag = 1;	/* Just to pass sanity checks */
			dst_ip_rand = 1;
			break;
		}
		dst_addr = libnet_name2addr6(l, optarg, LIBNET_RESOLVE);
		if (strncmp((char *)&dst_addr, (char *)&in6addr_error, sizeof(in6addr_error)) == 0) {
		  fprintf(stderr, "Bad destination IPv6 address!\n");
		  exit( -1 );
		}
		dst_addr_flag = 1;
		break;
	   case 's':
		if ( strcmp(optarg, "rand") == 0 ) {
			printf("Using random source IP's\n");
			src_addr_flag = 1;	/* Just to pass sanity checks */
			src_ip_rand = 1;
			break;
		}
		src_addr = libnet_name2addr6(l, optarg, LIBNET_RESOLVE);
		if (strncmp((char *)&src_addr, (char *)&in6addr_error, sizeof(in6addr_error)) == 0) {
		  fprintf(stderr, "Bad source IPv6 address!\n");
		  exit( -1 );
		}
		src_addr_flag = 1;
		break;
	   case 'r':
		seed = atoi(optarg);
		break;
	   case 'm':
		max_pushed = atol(optarg);
		break;
	   case 'k':
		skip = atol(optarg);
		printf("Will not transmit first %li packets.\n", skip);
		break;
	   case 'D':
		printout++;
		break;
	   case 'p':
		num_to_send = atoi(optarg);
		break;
	   case 'F':
		FragPct = atof(optarg);
		break;
	   case 'I':
		DstOpts = atof(optarg);
		break;
	   case 'i':
		ICMPCksm = atof(optarg);
		break;
	   case 'x':
		repeat = atoi(optarg);
		break;
	   case 'v':
		printf("Version %s\n", VERSION);
		exit(0);
	   }
	}

	if ( !src_addr_flag || !dst_addr_flag ) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	printf("Compiled against Libnet %s\n", LIBNET_VERSION);
	printf("Installing Signal Handlers.\n");
	if ( signal(SIGTERM, &sighandler) == SIG_ERR )
		printf("Failed to install signal handler for SIGTERM\n");
	if ( signal(SIGINT, &sighandler) == SIG_ERR )
		printf("Failed to install signal handler for SIGINT\n");
	if ( signal(SIGQUIT, &sighandler) == SIG_ERR )
		printf("Failed to install signal handler for SIGQUIT\n");

	printf("Seeding with %i\n", seed);
	srand(seed);
	max_pushed *= 1024;

	if ( (buf = malloc(IP_MAXPACKET)) == NULL ) {
		perror("malloc: ");
		exit( -1 );
	}


	if ( max_pushed >= 10000000 )
	 	printf("No Maximum traffic limiter\n");
	else printf("Maximum traffic rate = %.2f k/s\n", max_pushed/1024.0 );

	printf("Bad IPv6 Dst Opts Pcnt\t= %.0f%%\n", DstOpts);
	printf("Frag'd Pcnt\t= %.0f%%\t\t", FragPct);
	printf("Bad ICMP Cksm\t= %.0f%%\n", ICMPCksm);
	printf("\n");


	/* Drop them down to floats so we can multiply and not overflow */
	FragPct		/= 100;
	DstOpts		/= 100;
	ICMPCksm	/= 100;

    

	/*************
 	* Main Loop *
 	*************/
	gettimeofday(&tv, NULL);
	gettimeofday(&starttime, NULL);
	ver = 6;

	for(acx = 0; acx < num_to_send; acx++) {
		packet_len = IP6_H + ICMP6_H;
	
		hlim	= RAND8;
		flow	= RAND32;
		nxt		= IPPROTO_ICMPV6;
		icmp6 = (struct icmp6_hdr *) (buf + IP6_H); /* for no extension header case */

		if ( src_ip_rand == 1 ) {
		  (src_addr.__u6_addr.__u6_addr32)[0] = RAND32;
		  (src_addr.__u6_addr.__u6_addr32)[1] = RAND32;
		  (src_addr.__u6_addr.__u6_addr32)[2] = RAND32;
		  (src_addr.__u6_addr.__u6_addr32)[3] = RAND32;
		}
		if ( dst_ip_rand == 1 ) {
		  (dst_addr.__u6_addr.__u6_addr32)[0] = RAND32;
		  (dst_addr.__u6_addr.__u6_addr32)[1] = RAND32;
		  (dst_addr.__u6_addr.__u6_addr32)[2] = RAND32;
		  (dst_addr.__u6_addr.__u6_addr32)[3] = RAND32;
		}

		if ( rand() <= (RAND_MAX * FragPct) ) {
		  /* should add fragment header after IPv6 header */
		  f6_offlg = RAND16;
		  f6_id    = RAND32;
		  f6_nxt   = IPPROTO_ICMPV6;
		  f6_rsv   = RAND8;
		  nxt = IPPROTO_FRAGMENT;
		  icmp6 = (struct icmp6_hdr *) (buf + IP6_H + IP6_FRAGH); /* adjust the pointer */
		  ip6_fraghdr = (struct ip6_frag *)(buf + IP6_H);
		  frag_flag = 1;
		  packet_len += IP6_FRAGH;
		}

		if ( rand() <= (RAND_MAX * DstOpts) ) {
			/* should add Destination Options header */			
			dstopt_len = (int)(10.0*rand()/(RAND_MAX+1.0)); /* maximun 10 x 8 = 80 bytes */
			dstopt_nxt = IPPROTO_ICMPV6;
			dstopt_flag = 1;
			dstopt_tlen = (dstopt_len << 3) + 8;
			packet_len += dstopt_tlen;			
			if (frag_flag) {
				f6_nxt = IPPROTO_DSTOPTS;
				icmp6 = (struct icmp6_hdr *) (buf + IP6_H + IP6_FRAGH + dstopt_tlen);
				ip6_dopthdr = (struct ip6_dest *)(buf + IP6_H + IP6_FRAGH);
			}
			else {
				nxt = IPPROTO_DSTOPTS;
				icmp6 = (struct icmp6_hdr *) (buf + IP6_H + dstopt_tlen);
				ip6_dopthdr = (struct ip6_dest *)(buf + IP6_H);
			}
		}
		
		payload_s = rand() & 0x4ff;            /* length of 1279 */
		packet_len += payload_s;
		plen = packet_len - IP6_H;
		
		/*
 		*  Build the IPv6 header
 		*/
		ip6 = (struct ip6_hdr *) buf;
		ip6->ip6_flow   = htonl(flow);
		ip6->ip6_vfc    = ver<<4;              /* version 6 */
		ip6->ip6_plen   = htons(plen);         /* payload length */
		ip6->ip6_nxt    = nxt;                 /* next header value */
		ip6->ip6_hlim   = hlim;                /* hop limit */
		memcpy(&(ip6->ip6_src), &src_addr, sizeof(struct in6_addr));
		memcpy(&(ip6->ip6_dst), &dst_addr, sizeof(struct in6_addr));

		if (frag_flag) {
		  /* Build fragment header */
		  ip6_fraghdr->ip6f_nxt      = f6_nxt;   /* next header value */
		  ip6_fraghdr->ip6f_reserved = f6_rsv;   /* reserved field */
		  ip6_fraghdr->ip6f_offlg    = htons(f6_offlg); /* offset, reserved and flag */
		  ip6_fraghdr->ip6f_ident    = htonl(f6_id);    /* fragment id */
		}

		if (dstopt_flag) {
			/* Build destination options header */
			ip6_dopthdr->ip6d_nxt = dstopt_nxt;
			ip6_dopthdr->ip6d_len = dstopt_len; /* remember: it is 8 bytes by unit */
			payload = (u_short *)(ip6_dopthdr);
			payload[1] = RAND16;   /* set the 3rd and 4th bytes */
			payload[2] = RAND16;   /* set the 5-6th bytes */
			payload[3] = RAND16;   /* set the 7-8th bytes */
			/* set the remaining in the header */
			for (cx = 0; cx < (u_int)(dstopt_len << 2); cx+=1) {
				payload[cx+4] = RAND16;
			}
		}
		

		icmp6->icmp6_type = RAND8;
		icmp6->icmp6_code = RAND8;
		icmp6->icmp6_cksum= 0;
		icmp6->icmp6_data32[0] = RAND32;

		payload = (u_short *)((u_char *) icmp6 + ICMP6_H);
		for(cx = 0; cx <= (payload_s >> 1); cx+=1)
			payload[cx] = RAND16;


		if ( rand() <= (RAND_MAX * ICMPCksm) )
		  icmp6->icmp6_cksum = RAND16;
		else	{
		  libnet_do_checksum(l, (u_int8_t *)buf, IPPROTO_ICMP, packet_len - IP6_H);
		  printf("pl = %d, ICMPCksm = %f\n", packet_len, ICMPCksm);
		}
		/* should be libnet_do_checksum(l, (u_int8_t *)buf, IPPROTO_ICMPV6, packet_len); */

		if ( printout ) {
			printf("%s ->",
				inet_ntop(AF_INET6, &src_addr, addrbuf, INET6_ADDRSTRLEN));
			printf(" %s ver[%i] plen[%i] nxt[%i] hlim[%i]\n",
				inet_ntop(AF_INET6, &dst_addr, addrbuf, INET6_ADDRSTRLEN), 
			                  ver & 0xf, plen, nxt, hlim);
		}
		
		if ( skip <= acx ) {
			for ( cx = 0; cx < repeat; cx++ ) {
				c = libnet_write_raw_ipv6(l, buf, packet_len);
				if (c != -1)
				  datapushed+=c;
			}
			if ( c != (packet_len) )
				perror("Failed to send packet");
		} 

		if ( !(acx % 1000) ) {
			if ( acx == 0 )
				continue;
			gettimeofday(&tv2, NULL);
			sec = (tv2.tv_sec - tv.tv_sec)
			      - (tv.tv_usec - tv2.tv_usec) / 1000000.0;
			printf(" %li @ %.1f pkts/sec and %.1f k/s\n", acx,
				1000/sec, (datapushed / 1024.0) / sec);
			datapushed=0;
			gettimeofday(&tv, NULL);
		}

		/* Flood protection for low traffic limit only. */
		if ( max_pushed < 10000000 ) {
			gettimeofday(&tv2, NULL);
			sec = (tv2.tv_sec - tv.tv_sec)
		      		- (tv.tv_usec - tv2.tv_usec) / 1000000.0;
			if ( (datapushed / sec) >= max_pushed )
				usleep(10);	/* 10 should give up our timeslice */
		}
	}


	gettimeofday(&tv, NULL);
	printf("\nWrote %li packets in %.2fs @ %.2f pkts/s\n", acx,
		(tv.tv_sec-starttime.tv_sec)
		+ (tv.tv_usec-starttime.tv_usec) / 1000000.0,
		acx / ((tv.tv_sec-starttime.tv_sec)
                       + (tv.tv_usec-starttime.tv_usec)/1000000.0) );

	libnet_destroy(l);
	free(buf);
	return ( 0 );
}


void usage(char *name)
{
   fprintf(stderr,
	"usage: %s [-v] [-D] -s <source ip> -d <destination ip>\n"
	"          [-r seed] [-m <max kB/s to generate>]\n"
	"          [-p <pkts to generate>] [-k <skip packets>] [-x <repeat times>]\n\n"
	"       Percentage Opts: [-F frags] [-I <IPv6 Destination Options>]\n"
	"                        [-i <Bad ICMP checksum>]\n\n"
	"       [-D] causes packet info to be printed out -- DEBUGGING\n\n"
	"       ex: -s 2001:1:2:3:4::1     -d 2001:1:2:3:4::2 -I 100\n"
	"           will give a 100%% chance of IPv6 Destination ^^^ Options \n"
	"       ex: -s 2001:a:b:c:d::1     -d 2001:a:b:c:d::2 -p 100 -r 103334\n"
	"       ex: -s rand -d rand -r 23342\n"
	"              ^^^^ causes random source addr\n"
	"       ex: -s rand -d rand -k 10000 -p 10001 -r 666\n"
	"           Will only send the 10001 packet with random seed 666\n"
	"           this is especially useful if you suspect that packet is\n"
	"           causing a problem with the target stack.\n\n",
	((char *) rindex(name, '/')) == ((char *) NULL)
		? (char *) name
		: (char *) rindex(name, '/') + 1);
}

void sighandler(int sig)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	printf("\n");
	printf("Caught signal %i\n", sig);

	printf("Used random seed %i\n", seed);
	printf("Wrote %li packets in %.2fs @ %.2f pkts/s\n", acx,
		(tv.tv_sec - starttime.tv_sec)
		  + (tv.tv_usec - starttime.tv_usec)/1000000.0,
		acx / (( tv.tv_sec - starttime.tv_sec)
		  + (tv.tv_usec - starttime.tv_usec)/1000000.0)
		);

	fflush(stdout);
	exit(0);
}
