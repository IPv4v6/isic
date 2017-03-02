#include "isic.h"

/*
 * ISIC6 - IPv6 Stack Integrity Checker
 *
 * This is tuned for ethernet sized frames (1500 bytes)
 * For user over a modem or frame (or other) you will have to change the
 * MPS line below.  The MPS needs to be less than the size of the frame 
 * size minus the length of the IPv6 header (40 bytes IIRC)
 */


/* Variables shared between main and the signal handler so we can display
 * output if ctrl-c'd
 */
u_int seed = 0;
u_long acx = 0;
struct timeval starttime;
u_long datapushed = 0;			/* How many bytes we pushed */
#define MPS 1400.0                      /* Maximum Payload Size */


int
main(int argc, char **argv)
{
	int c, frag_flag = 0, hopt_flag = 0;
	u_char *buf = NULL, *pointer = NULL;
	u_short	*payload = NULL;
	u_int payload_s = 0, upperlayer_s = 0;
	char addrbuf[INET6_ADDRSTRLEN];

	/* libnet variables */
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *l;
	char *device = NULL;

	/* Packet Variables */
	struct ip6_hdr *ip6 = NULL;
	struct libnet_in6_addr src_addr;
	struct libnet_in6_addr dst_addr;
	u_int src_addr_flag = 0, dst_addr_flag = 0;

	u_char ver, hlim, nxt;
	u_int16_t plen;
	u_int32_t flow;

	struct ip6_hbh  *ip6_hopthdr = NULL; /* IPv6 Hop-by-Hop options header */
	u_char hopt_nxt = 0, hopt_len = 0;
	u_int hopt_tlen = 0; /* total length in byte for IPv6 Hop-by-Hop Opts */

	struct ip6_frag *ip6_fraghdr = NULL; /* IPv6 fragment header */
	u_char f6_nxt = 0, f6_rsv = 0;
	u_int32_t f6_id = 0;
	u_int16_t f6_offlg = 0;

	/* Functionality Variables */
	int src_ip_rand = 0, dst_ip_rand = 0;
	struct timeval tv, tv2;
	float sec;
	unsigned int cx = 0;
	u_long max_pushed = 10240;		/* 10MB/sec */
	u_long num_to_send = 0xffffffff;	/* Send 4billion packets */
	u_long skip = 0; 			/* Skip how many packets */
	int printout = 0;			/* Debugging */
	u_int repeat = 1;			/* How many times to send each packet */

	/* Defaults */
	float FragPct	=	10; /* fragment header percentage */
	float BadIPVer	=	10; /* bad IP Version percentage */
	float PLength	=	10; /* bad payload length percentage */
	float BadHOpts	=	10; /* bad Hop-by-Hop option header */

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
                
	while((c = getopt(argc, argv, "hd:H:I:s:r:m:k:DP:p:V:F:vx:")) != EOF) {
	  switch (c) {
	   case 'h':
		usage(argv[0]);
		exit(0);
		break;
	   case 'd':
		if ( strncmp(optarg, "rand", sizeof("rand")) == 0 ) {
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
		if ( strncmp(optarg, "rand", sizeof("rand")) == 0 ) {
			printf("Using random source IP's\n");
			src_addr_flag = 1;	/* Just to pass sanity checks */
			src_ip_rand = 1;
			break;
		}
		src_addr = libnet_name2addr6(l, optarg, LIBNET_RESOLVE);
		if (strncmp((char *)&dst_addr, (char *)&in6addr_error, sizeof(in6addr_error)) == 0) {
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
	   case 'V':
		BadIPVer = atoi(optarg);
		break;
	   case 'F':
		FragPct = atof(optarg);
		break;
	   case 'P':
		PLength = atof(optarg);
		break;
	   case 'H':
		BadHOpts = atof(optarg);
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

        printf("Bad IP Version\t= %.0f%%\t\t", BadIPVer);
        printf("Odd Payload Length\t= %.0f%%\n", PLength);
        printf("Frag'd Pcnt\t= %.0f%%\t\t", FragPct);
	printf("Bad Hop-by-Hop Options\t= %.0f%%\n", BadHOpts);

	/* Drop them down to floats so we can multiply and not overflow */
	BadIPVer /= 100;
	FragPct	 /= 100;
	PLength	 /= 100;
	BadHOpts /= 100;
    

	/*************
 	* Main Loop *
 	*************/
	gettimeofday(&tv, NULL);
	gettimeofday(&starttime, NULL);

	for(acx = 0; acx < num_to_send; acx++) {
	
		flow	= RAND32;
		hlim	= RAND8;
		nxt	= RAND8;

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
		
		if ( rand() <= (RAND_MAX * BadIPVer ) )
			ver = RAND8;
		else	ver = 6;
		
		payload_s = 0;

		if ( rand() <= (RAND_MAX * BadHOpts) ) {
			/* should add Hop-by-Hop Options header */
			nxt = IPPROTO_HOPOPTS;
			hopt_len = (u_char)(124.0*rand()/(RAND_MAX+1.0)); /* maximun 125 x 8 = 1000 bytes */
			hopt_nxt = RAND8;
			hopt_flag = 1;
			hopt_tlen = (hopt_len << 3) + 8;
			payload_s += hopt_tlen;
		}

		if ( rand() <= (RAND_MAX * FragPct) ) {
		  /* should add fragment header */
			frag_flag = 1;
			f6_offlg = RAND16;
			f6_id    = RAND32;
			f6_nxt   = RAND8;
			f6_rsv   = RAND8;
			payload_s += IP6_FRAGH;
			if (hopt_flag)
				hopt_nxt = IPPROTO_FRAGMENT;
			else				
				nxt = IPPROTO_FRAGMENT;				
		}
		
		upperlayer_s = (u_int)((MPS-payload_s)*rand()/(RAND_MAX+1.0));
		payload_s += upperlayer_s;

		if ( rand() <= (RAND_MAX * PLength ) )
		  plen = RAND16;
		else
		  plen = payload_s;
		  
		/* Build the IPv6 header */
		ip6 = (struct ip6_hdr *) buf;
		ip6->ip6_flow   = htonl(flow);
		ip6->ip6_vfc    = ver<<4;              /* version 6 */
		ip6->ip6_plen   = htons(plen);         /* payload length */
		ip6->ip6_nxt    = nxt;                 /* next header value */
		ip6->ip6_hlim   = hlim;                /* hop limit */
		memcpy(&(ip6->ip6_src), &src_addr, sizeof(struct in6_addr));
		memcpy(&(ip6->ip6_dst), &dst_addr, sizeof(struct in6_addr));
		pointer = buf + IP6_H;

		if (hopt_flag) {
		  /* Build hop-by-hop options header */
		  payload = (u_short *)pointer;
		  ip6_hopthdr = (struct ip6_hbh *)pointer;
		  ip6_hopthdr->ip6h_nxt = hopt_nxt;
		  ip6_hopthdr->ip6h_len = hopt_len; /* remember: it is 8 bytes by unit */
		  pointer[2] = RAND16;   /* set the 3rd and 4th bytes */
		  pointer[4] = RAND32;   /* set the 5-8th bytes */
		  for (cx = 0; cx < (u_int)(hopt_len << 2); cx+=1)
		    pointer[cx+8] = RAND16;
		  pointer += hopt_tlen;
		}

		/* printf("p_size = %d, u_size = %d, o_tlen = %d\n", payload_s, upperlayer_s, hopt_tlen); */

		if (frag_flag) {
		  /* Build fragment header */
		  ip6_fraghdr = (struct ip6_frag *)pointer;
		  ip6_fraghdr->ip6f_nxt      = f6_nxt;   /* next header value */
		  ip6_fraghdr->ip6f_reserved = f6_rsv;   /* reserved field */
		  ip6_fraghdr->ip6f_offlg    = htons(f6_offlg); /* offset, reserved and flag */
		  ip6_fraghdr->ip6f_ident    = htonl(f6_id);    /* fragment id */
		  pointer += IP6_FRAGH;
		}
		
		payload = (u_short *)pointer;
		for(cx = 0; cx <= (upperlayer_s >> 1); cx+=1)
		  payload[cx] = RAND16;
		payload[upperlayer_s] = RAND16;
		

		if ( printout ) {
			printf("%s\t->",
				inet_ntop(AF_INET6, &src_addr, addrbuf, INET6_ADDRSTRLEN));
			printf(" %s\tver[%i]\tplen[%i]\tnxt[%i]  \thlim[%i]\n",
				inet_ntop(AF_INET6, &dst_addr, addrbuf, INET6_ADDRSTRLEN), 
			                  ver & 0xf, plen, nxt, hlim);
		}
			
		if ( skip <= acx ) {
		  for ( cx = 0; cx < repeat; cx++ ) {
		    c = libnet_write_raw_ipv6(l, buf, IP6_H + payload_s);
		    if (c != -1)
		      datapushed+=c;
		  }
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
	"          [-p <pkts to generate>] [-k <skip packets>] [-x <repeat times>]\n"
	"          [-r <random seed>] [-m <max kB/s to generate>]\n\n"
	"       Percentage Opts: [-F frags] [-H <Bad IPv6 Hop-by-Hop Options]\n"
	"                        [-V <Bad IP Version>] [-P <Random payload length>]\n"
	"notes:\n"
	"	[-D] causes packet info to be printed out -- DEBUGGING\n\n"
	"       ex: -s 2001:2:3:4::1  -d 2001:a:b::1 -F 100\n"
	"        100%% of the packets will has fragment ^^^^ header\n"
	"       ex: -s 2001:2:3:4::1  -d 2001:a:b::1 -p 100 -r 103334\n"
	"       ex: -s rand -d rand -r 23342\n"
	"              ^^^^ causes random source addr\n"
	"       ex: -s rand -d rand -k 10000 -p 10001 -r 666\n"
	"           Will only send the 10001 packet with random seed 666\n"
	"           this is especially useful if you suspect that packet is\n"
	"           causing a problem with the target stack.\n"
	"\n",
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
