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


char *atoether( char * );

int
main(int argc, char **argv)
{
	int c;
	u_char *buf = NULL;
	u_short	*payload = NULL;
	u_int payload_s = 0;
	int packet_len = 0;
	char device[128] = "";

	struct ether_addr *ea = NULL;
	struct ether_header *ether = NULL;
	struct ip *ip_hdr = NULL;
	struct udphdr *udp = NULL;
	u_short *ip_opts = NULL;

	/* libnet variables */
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *l = NULL;

	/* Packet Variables */
	u_int32_t src_ip = 0, dst_ip = 0;
	u_short src_prt = 0, dst_prt = 0;
	u_char tos, ttl, ver;
	u_int id, frag_off;
	u_int ipopt_len;
	u_char first_octets[] = {224, 225, 232, 233, 234, 235, 236, 237, 238, 239};
	size_t octet_array_size = (sizeof(first_octets) / sizeof(first_octets[0]));
	u_char compare[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	u_char dhost[] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x00};
	u_char shost[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	u_int16_t proto = htons(ETHERTYPE_IP);

	/* Functionality Variables */
	int src_ip_rand = 0, dst_ip_rand = 0;
	int src_mac_rand = 0;
	struct timeval tv, tv2;
	float sec;
	unsigned int cx = 0;
	u_long max_pushed = 10240;		/* 10MB/sec */
	u_long num_to_send = 0xffffffff;	/* Send 4billion packets */
	u_long skip = 0; 			/* Skip how many packets */
	int printout = 0;			/* Debugging */
	int dst_port_rand = 0;
	int src_port_rand = 0;
	char *tmp_port = NULL;
	u_int repeat = 1;

	/* Defaults */
	float FragPct	=	10;
	float BadIPVer	=	10;
	float IPOpts	=	10;
	float UDPCksm	=	10;

	/* Not crypto strong randomness but we don't really care.  And this  *
	 * gives us a way to determine the seed while the program is running *
 	 * if we need to repeat the results				     */
	seed = getpid();
    
	while((c = getopt(argc, argv, "i:hd:s:r:m:k:Dp:V:F:I:U:vx:z:")) != EOF) {
	  switch (c) {
	   case 'z':
		if ( strcmp(optarg, "rand") == 0 ) {
			printf("Using random source MAC's\n");
			shost[0] = 0xff;
			src_mac_rand = 1;
			break;
		}
		bcopy(atoether(optarg), shost, 6);
		break;
	   case 'i':
		if (rindex(optarg, '/'))
			strncpy(device, (char *) rindex(optarg, '/')+1, 128);
		else
			strncpy(device, optarg, 128);
		device[127] = '\0';
		break;
	   case 'h':
		usage(argv[0]);
		exit(0);
		break;
	   case 'd':
		dst_port_rand = 1;
		if ( (tmp_port = index(optarg, ',')) != NULL ) {
			*tmp_port++ = '\0';
			dst_port_rand = 0;
			dst_prt = htons((u_int) atol(tmp_port));
		}
		if ( strcmp(optarg, "rand") == 0 ) {
			printf("Using random multicast dest IP's\n");
			dst_ip = 1;	/* Just to pass sanity checks */
			dst_ip_rand = 1;
			break;
		}
		if ((dst_ip = libnet_name2addr4(l, optarg, LIBNET_RESOLVE)) == (u_int32_t)-1) {
			fprintf(stderr, "Bad dest IP\n");
			exit( -1 );
		}
		break;
	   case 's':
		src_port_rand = 1;
		if ( (tmp_port = index(optarg, ',')) != NULL ) {
			*tmp_port++ = '\0';
			src_port_rand = 0;
			src_prt = htons((u_int) atol(tmp_port));
		}
		if ( strcmp(optarg, "rand") == 0 ) {
			printf("Using random source IP's\n");
			src_ip = 1;	/* Just to pass sanity checks */
			src_ip_rand = 1;
			break;
		}
		if ((src_ip = libnet_name2addr4(l, optarg, LIBNET_RESOLVE)) == (u_int32_t)-1) {
			fprintf(stderr, "Bad source IP\n");
			exit( -1 );
		}
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
		BadIPVer = atof(optarg);
		break;
	   case 'F':
		FragPct = atof(optarg);
		break;
	   case 'I':
		IPOpts = atof(optarg);
		break;
	   case 'U':
		UDPCksm = atof(optarg);
		break;
	   case 'x':
		repeat = atoi(optarg);
		break;
	   case 'v':
		printf("Version %s\n", VERSION);
		exit(0);
	   }
	}

	if ( *device == '\0' || !src_ip || !dst_ip ) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Initialize libnet context, Root priviledges are required.*/ 
	l = libnet_init(
            LIBNET_LINK_ADV,                        /* injection type */
            device,                                 /* network interface */
            errbuf);                                /* error buffer */

	if (l == NULL) {
	  fprintf(stderr, "libnet_init() failed: %s", errbuf);
	  exit( -1 );
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

	if ( src_port_rand )
		printf("Using random source ports.\n");
	if ( dst_port_rand )
		printf("Using random destination ports.\n");

	if ( (buf = malloc(ETHER_FRAME_SIZE)) == NULL ) {
		perror("malloc: ");
		exit( -1 );
	}
    bzero(buf, ETHER_FRAME_SIZE);
    ether = (struct ether_header *) buf;
    ether->ether_type = proto;

    if ( bcmp(shost, compare, 6) == 0 ) {
		if ( (ea = (struct ether_addr *)libnet_get_hwaddr(l)) == 0 )
			fprintf(stderr, "Cannot get MAC for %s: %s", device, libnet_geterror(l));
		bcopy(ea, ether->ether_shost, 6);
	} else	bcopy(shost, ether->ether_shost, 6);

    bcopy(dhost, ether->ether_dhost, 3);

    if ( !src_mac_rand )
		printf("Sending from MAC %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			ether->ether_shost[0], ether->ether_shost[1],
			ether->ether_shost[2], ether->ether_shost[3],
			ether->ether_shost[4], ether->ether_shost[5]);
	else	printf("Sending from random MAC addresses.\n");
    
	if ( max_pushed >= 10000000 )
	 	printf("No Maximum traffic limiter\n");
	else printf("Maximum traffic rate = %.2f k/s\n", max_pushed/1024.0 );

	printf("Bad IP Version\t= %.0f%%\t\t", BadIPVer);
	printf("IP Opts Pcnt\t= %.0f%%\n", IPOpts);

	printf("Frag'd Pcnt\t= %.0f%%\t\t", FragPct);
	printf("Bad UDP Cksm\t= %.0f%%\n", UDPCksm);
	printf("\n");


	/* Drop them down to floats so we can multiply and not overflow */
	BadIPVer	/= 100;
	FragPct		/= 100;
	IPOpts		/= 100;
	UDPCksm		/= 100;

    

	/*************
 	* Main Loop *
 	*************/
	gettimeofday(&tv, NULL);
	gettimeofday(&starttime, NULL);

	for(acx = 0; acx < num_to_send; acx++) {
		if ( src_mac_rand ) {
			((u_int16_t *) ether->ether_shost)[0] = RAND16;
			((u_int16_t *) ether->ether_shost)[1] = RAND16;
			((u_int16_t *) ether->ether_shost)[2] = RAND16;
		}

		packet_len = IP_H + UDP_H;
	
		tos	= RAND8;
		id	= acx & 0xffff;
		ttl	= RAND8;


		if ( rand() <= (RAND_MAX * FragPct) )
			frag_off = RAND16;
		else	frag_off = 0;

		/* We're not going to pad IP Options */
		if ( rand() <= (RAND_MAX * IPOpts) ) {
			ipopt_len = 10 * (rand() / (float) RAND_MAX);
			ipopt_len = ipopt_len << 1;
			ip_opts = (u_short *) (buf + 14);
			packet_len += ipopt_len << 1;

			for ( cx = 0; cx < ipopt_len; cx++ )
				ip_opts[cx] = RAND16;
			udp = (struct udphdr *) ((buf + 14) + IP_H + (ipopt_len << 1));
			ipopt_len = ipopt_len >> 1;
		} else {
			ipopt_len = 0;
			udp = (struct udphdr *) ((buf + 14) + IP_H);
		}

		if ( src_ip_rand == 1 )
			src_ip = RAND32;
		if ( dst_ip_rand == 1 ) {
			u_char first_octet = first_octets[rand() % octet_array_size];
			dst_ip = ((RAND16 << 16) + (RAND8 << 8) + first_octet); /* little-endian */
        	}

		ether->ether_dhost[3] = (dst_ip & 0x00007f00) >> 8;
		ether->ether_dhost[4] = (dst_ip & 0x00ff0000) >> 16; 
		ether->ether_dhost[5] = (dst_ip & 0xff000000) >> 24;

		if ( rand() <= (RAND_MAX * BadIPVer ) )
			ver = rand() & 0xf;
		else	ver = 4;

		payload_s = rand() & 0x4ff;            /* length of 1279 */
		packet_len += payload_s;

		/*
 		 *  Build the IP header
 		 */
		ip_hdr = (struct ip *) (buf + 14);
		ip_hdr->ip_v    = ver;                 /* version 4 */
		ip_hdr->ip_hl   = 5 + ipopt_len;       /* 20 byte header */
		ip_hdr->ip_tos  = tos;                 /* IP tos */
		ip_hdr->ip_len  = htons(packet_len);   /* total length */
		ip_hdr->ip_id   = htons(id);           /* IP ID */
		ip_hdr->ip_off  = htons(frag_off);     /* fragmentation flags */
		ip_hdr->ip_ttl  = ttl;                 /* time to live */
		ip_hdr->ip_p    = IPPROTO_UDP;         /* transport protocol */
		ip_hdr->ip_sum  = 0;                   /* do this later */
		ip_hdr->ip_src.s_addr = src_ip;
		ip_hdr->ip_dst.s_addr = dst_ip;
		
		if ( src_port_rand == 1 )
			udp->uh_sport = RAND16;
		else	udp->uh_sport = src_prt;
		if ( dst_port_rand == 1 )
			udp->uh_dport = RAND16;
		else	udp->uh_dport = dst_prt;


		udp->uh_ulen	= htons(payload_s + UDP_H);
		udp->uh_sum	= 0;

		payload = (u_short *)((u_char *) udp + UDP_H);
		for(cx = 0; cx <= (payload_s >> 1); cx+=1)
			payload[cx] = RAND16;

		if ( printout ) {
			printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x -> ",
	                       ether->ether_shost[0], ether->ether_shost[1],
			       ether->ether_shost[2], ether->ether_shost[3],
			       ether->ether_shost[4], ether->ether_shost[5]);
		        printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x  ::  ",
		               ether->ether_dhost[0], ether->ether_dhost[1],
		               ether->ether_dhost[2], ether->ether_dhost[3],
		               ether->ether_dhost[4], ether->ether_dhost[5]);
			printf("%s,%i ->",
				inet_ntoa(*((struct in_addr*) &src_ip )),
				htons(udp->uh_sport) );
			printf(" %s,%i tos[%i] id[%i] ver[%i] frag[%i]\n",
				inet_ntoa(*((struct in_addr*) &dst_ip )), 
				htons(udp->uh_dport), tos, id, ver, frag_off);
		}
				
		
		if ( rand() <= (RAND_MAX * UDPCksm) )
			udp->uh_sum = RAND16;
		else {
			libnet_do_checksum(l, (u_int8_t *)(buf + 14), IPPROTO_IP, packet_len);
			libnet_do_checksum(l, (u_int8_t *)(buf + 14), IPPROTO_UDP, UDP_H + payload_s);
		}

 		 
		if ( skip <= acx ) {
			for ( cx = 0; cx < repeat; cx++ ) {
				c = libnet_adv_write_link(l, buf, (packet_len + 14));
				if (c != -1)
				  datapushed+=c;
			}
			if (c < (packet_len) ) {
				perror("Failed to send packet");
		/*		printf("%s ->", 
		 *		     inet_ntoa(*((struct in_addr*) &src_ip )));
		 *
		 *		printf(" %s tos[%i] id[%i] ver[%i] "
		 *		     "frag[%i]\n",
		 *		     inet_ntoa(*((struct in_addr*) &dst_ip )),
		 *			tos, id, ver, frag_off);
		 */
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


		/* Flood protection for low traffic only. */
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

char *atoether( char *txt )
{
	static char retval[6];
	int ret_pos = 0;
	int len = 0;
	int val = 0;
	int cx = 0;

	len = strlen(txt);
	bzero(retval, 6);

	for (ret_pos = 0, cx = 0; cx < len; cx++) {
		if ( txt[cx] == '\0' )
			return( retval );
		if ( (txt[cx] == ':') || (txt[cx] == '-') ) {
			ret_pos++;
			val = 0;
			continue;
		}
		/* Shutdup */
		switch ( txt[cx] ) {
			case '0':	val = 0;  break;
			case '1':	val = 1;  break;
			case '2':	val = 2;  break;
			case '3':	val = 3;  break;
			case '4':	val = 4;  break;
			case '5':	val = 5;  break;
			case '6':	val = 6;  break;
			case '7':	val = 7;  break;
			case '8':	val = 8;  break;
			case '9':	val = 9;  break;
			case 'A':
			case 'a':	val = 10; break;
			case 'B':
			case 'b':	val = 11; break;
			case 'C':
			case 'c':	val = 12; break;
			case 'D':
			case 'd':	val = 13; break;
			case 'E':
			case 'e':	val = 14; break;
			case 'F':
			case 'f':	val = 15; break;
		}
		retval[ret_pos] = (u_int8_t) (((retval[ret_pos]) << 4) + val);
	}
	
	return( retval );
}

void usage(char *name)
{
   fprintf(stderr,
	"usage: %s [-v] [-D] -s <source ip>[,port] -d <destination ip>[,port]\n"
	"          [-r seed] [-m <max kB/s to generate>] -i [interface]\n"
	"          [-p <pkts to generate>] [-k <skip packets>] [-x <repeat times>]\n"
	"          [-z <source MAC>]\n\n"
	"       Percentage Opts: [-F frags] [-V <Bad IP Version>] [-I <IP Options>]\n"
	"                        [-U <UDP Checksum>]\n\n"
	"       [-D] causes packet info to be printed out -- DEBUGGING\n\n"
	"       This tool sends out UDP packets with random or specified multicast\n"
	"       destination IP address.\n\n"
	"       ex: -s 10.10.10.10,23 -d 224.10.10.100 -I 100\n"
	"           will give a 100%% chance of IP Options ^^^\n"
	"       ex: -s 10.10.10.10,23  -d 239.10.10.100 -p 100 -r 103334\n"
	"       ex: -s rand -d rand,1234 -r 23342\n"
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
