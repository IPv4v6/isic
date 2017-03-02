
/* Link Level scan */

/* COOL!!!!  Linux can send out short ether frames!
 */

/* ARGHH!!!!!  The IEEE specifies things in bitwise little-endian order.
 */

#if !defined(linux)
#define __GLIBC__	1	/* XXX */
#endif

#include "isic.h"


char *atoether(char *);

int main(int argc, char **argv)
{
	u_char compare[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	u_char dhost[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	u_char shost[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	struct ether_header *ether = NULL;
	u_int16_t proto = htons(ETHERTYPE_IP);
	struct ether_addr *ea = NULL;
	u_int16_t *data = NULL;
	char dev[128] = "";
	u_char *buf = NULL;
	int proto_rand = 0;
	struct timeval tv, tv2;
	int max_len = ETHER_FRAME_SIZE;
	u_long count = 0xffffffffl;
	u_long data_pushed = 0;
	struct ip *ip = NULL;
	u_long data_len = 0;
	int rand_source = 0;
	int rand_dest = 0;
	long mark = 1000;
        u_long skip = 0;           /* Skip how many packets */
	u_long acx = 0;
	int debug = 0;
	u_int len = 0;
	u_int cx = 0;
	float sec;
	int seed;
	u_int c;

	/* libnet variables */
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *l;

	seed = getpid();

	while((c=getopt(argc, argv, "hi:s:d:k:p:r:c:l:Dvm:")) != (unsigned) EOF) {
	  switch (c) {
	  case 'i':
		if (rindex(optarg, '/'))
			strncpy(dev, (char *) rindex(optarg, '/')+1, 128);
		else
			strncpy(dev, optarg, 128);
		dev[127] = '\0';
		break;
	  case 's':
		if ( strcmp(optarg, "rand") == 0 ) {
			printf("Using random source MAC's\n");
			shost[0] = 0xff;
			rand_source = 1;
			break;
		}
		bcopy(atoether(optarg), shost, 6);
		break;
	  case 'd':
		if ( strcmp(optarg, "rand") == 0 ) {
			printf("Using random destination MAC's\n");
			dhost[0] = 0xff;
			rand_dest = 1;
			break;
		}
		bcopy(atoether(optarg), dhost, 6);
		break;
	  case 'r':
		seed = atoi(optarg);
		break;
	  case 'c':
		count = atol(optarg);
		break;
	  case 'm':
		mark = atol(optarg);
		if (mark <= 0)
			exit(printf("Please use a positive arg for -m\n"));
		break;
	  case 'k':
		skip = atol(optarg);
		printf("Will not transmit first %li packet(s).\n", skip);
		break;
	  case 'D':
		debug++;
		break;
	  case 'l':
		max_len = atoi(optarg);
		if ( max_len > 1500 ) {
			printf("Maximum Length of %i is longer than the max "
				"ethernet frame size of %i\n", max_len,
				ETHER_FRAME_SIZE);
			exit(0);
		}
		if ( max_len <  14) {
			printf("You seam to have entered %i as the maximum "
				"length...  Please make it >= 14\n", max_len);
			exit(0);
		}
		break;
	  case 'p':
		if ( strcasecmp(optarg, "rand") == 0 ) {
			proto_rand++;
			break;
		}
		proto_rand = 0;
		proto = htons(atoi(optarg));
		break;
	   case 'v':
		printf("Version %s\n", VERSION);
		exit(0);
	  case 'h':
	  default:
		usage(argv[0]);
		exit( 0 );
	  }
	}


	if ( *dev == '\0' ) {
		usage(argv[0]);
		exit( 0 );
	}

	/* Initialize libnet context, Root priviledges are required.*/ 
	l = libnet_init(
            LIBNET_LINK_ADV,                        /* injection type */
            dev,                                    /* network interface */
            errbuf);                                /* error buffer */

	if (l == NULL) {
	  fprintf(stderr, "Can not initialize libnet: %s", errbuf);
	  exit( -1 );
	}

	max_len -= 6 + 6 + 2;

	printf("Seeding with %i\n", seed);
	srand(seed);

	if ( (buf = malloc(ETHER_FRAME_SIZE)) == NULL ) {
		perror("malloc");
		exit( -1 );
	}
	bzero(buf, ETHER_FRAME_SIZE);
	ether = (struct ether_header *) buf;

	if ( bcmp(dhost, compare, 6) == 0 )
		memset(ether->ether_dhost, 0xff, 6);
	else	bcopy(dhost, ether->ether_dhost, 6);
	if ( bcmp(shost, compare, 6) == 0 ) {
		if ( (ea = (struct ether_addr *)libnet_get_hwaddr(l)) == 0 )
			fprintf(stderr, "Cannot get MAC for %s: %s", dev, libnet_geterror(l));
		bcopy(ea, ether->ether_shost, 6);
	} else	bcopy(shost, ether->ether_shost, 6);


	printf("Maximum packet size (minus header) is %i bytes\n", max_len);
	if ( proto_rand )
		printf("Ethernet protocols will be randomized.\n");
	else	printf("Ethernet protocol will be %i.\n", ntohs(proto));


	if ( !rand_dest )
		printf("Sending to MAC %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			ether->ether_dhost[0], ether->ether_dhost[1],
			ether->ether_dhost[2], ether->ether_dhost[3],
			ether->ether_dhost[4], ether->ether_dhost[5]);
	else	printf("Sending to random MAC addresses.\n");
	if ( !rand_source )
		printf("Sending from MAC %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			ether->ether_shost[0], ether->ether_shost[1],
			ether->ether_shost[2], ether->ether_shost[3],
			ether->ether_shost[4], ether->ether_shost[5]);
	else	printf("Sending from random MAC addresses.\n");

	ip = (struct ip *) (buf + 14);

	data = (u_int16_t *) (buf + 14);
	printf("Sending...\n");
	gettimeofday(&tv, NULL);
	for ( acx = 1; acx <= count; acx++ ) {
		len = sizeof(struct ether_header);

		if ( rand_source ) {
			((u_int16_t *) ether->ether_shost)[0] = RAND16;
			((u_int16_t *) ether->ether_shost)[1] = RAND16;
			((u_int16_t *) ether->ether_shost)[2] = RAND16;
		}
		if ( rand_dest ) {
			((u_int16_t *) ether->ether_dhost)[0] = RAND16;
			((u_int16_t *) ether->ether_dhost)[1] = RAND16;
			((u_int16_t *) ether->ether_dhost)[2] = RAND16;
		}
		if ( proto_rand )
			ether->ether_type = RAND16;
		else	ether->ether_type = proto;

		data_len = (u_int) (max_len * (rand()/((float) RAND_MAX + 1)));
		data_len >>= 1;
		for ( cx = 0; cx < data_len; cx++ )
			data[cx] = RAND16;
		data_len <<= 1;
		if ( rand() & 0x1 ) {
			data_len++;
			data[cx] = RAND16;
		}
		len += data_len;
	
		ip->ip_len = htons(data_len);
		ip->ip_sum = 0;
		libnet_do_checksum(l, (u_int8_t *) ip, IPPROTO_IP, data_len);

		if ( debug ) {
		   	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x  ->  ",
				ether->ether_shost[0], ether->ether_shost[1],
				ether->ether_shost[2], ether->ether_shost[3],
				ether->ether_shost[4], ether->ether_shost[5]);
		   	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t",
				ether->ether_dhost[0], ether->ether_dhost[1],
				ether->ether_dhost[2], ether->ether_dhost[3],
				ether->ether_dhost[4], ether->ether_dhost[5]);
			switch( ntohs(ether->ether_type) ) {
				case ETHERTYPE_IP:
					printf("Proto IP  \t");
					break;
				case ETHERTYPE_ARP:
					printf("Proto ARP \t");
					break;
				case ETHERTYPE_PUP:
					printf("Proto PUP \t");
					break;
				case ETHERTYPE_REVARP:
					printf("Proto RARP\t");
					break;
				case ETHERTYPE_VLAN:
					printf("Proto VLAN\t");
					break;
				default:
					printf("Proto %u\t",
						ntohs(ether->ether_type));
			}
			printf("Length %i\n", len);
		}

		if ( acx >= skip ) {
			c = libnet_adv_write_link(l, buf, len);
			if (c !=(u_int) -1)
		  		data_pushed += c;
		}

	/*	if ( c != len ) 
	 * 		perror("write_ll");
	 */ 
		if ( !(acx % mark) ) {
			gettimeofday(&tv2, NULL);
			sec = (tv2.tv_sec - tv.tv_sec)
				- (tv.tv_usec - tv2.tv_usec) / 1000000.0;
			printf(" %8lu @ %.1f pkts/sec and %.1f k/s\n", acx,
				mark/sec, (data_pushed/1024.0)/sec );
			data_pushed = 0;
			gettimeofday(&tv, NULL);
		}
	}

        if ((acx-1) % mark) {       /* There is a remainder */
		gettimeofday(&tv2, NULL);
		sec = (tv2.tv_sec - tv.tv_sec)
			- (tv.tv_usec - tv2.tv_usec) / 1000000.0;
		printf(" %8lu @ %.1f pkts/sec and %.1f k/s\n", acx-1,
			((acx-1) % mark)/sec, (data_pushed/1024.0)/sec );
	}

	libnet_destroy(l);
	free( buf );
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



void
usage(char *name)
{
	printf(
"usage: %s -i interface [-s <source MAC>] [-d <destination MAC>]\n"
"          [-p <protocol #> or 'rand'>]   [-r <random seed>]\n"
"          [-c <# of pkts to send>] [-k <skip packets>] \n"
"          [-l <max pkt length>] [-m <# of pkts between printout>]\n\n"
"       - Be careful, the source MAC defaults to your interface\n"
"         and the dest MAC defaults to broadcast\n"
"       - You can use 'rand' for the source and/or the dest MAC\n\n"
"	examples:\n"
"		esic -i eth0 -d 02:de:ad:be:ef:40 -r123 -c10000\n"
"		esic -i ep0 -s 01:02:34:56:07:89 -p rand -m5000\n\n",
		(char *) (index(name, '/') == NULL)
			? (char *) name
			: (char *) (rindex(name, '/') + 1) );
}
