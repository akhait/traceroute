#include <iostream>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <poll.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <linux/errqueue.h>
#include "trace.h"

#define REQ_DATASIZE 64 

using namespace std;

int main(int argc, char **argv) {
	Config conf;
	int retval, UDPsock;
	struct addrinfo *conn;
	struct timeval time;
	retval = checkArgs(argc, argv, &conf);
	if (retval == -1)
		return retval;
	if ((conn = connectionSetup(conf.ip_addr, conf.mod6)) == NULL)
		return -1;
	//Traceroute cycle
	int ttl = conf.first_ttl-1;
	bool done = false;
	do {
		++ttl;
		//Create socket
	    if ((UDPsock = createUDPSocket(ttl, conf.mod6)) == -1)
        	return UDPsock;
		//Send ping
	    if ((sendPing(UDPsock, conn)) == -1)
			return -1;
		//Get time
		gettimeofday(&time, NULL);
		double from = (time.tv_sec*1000.0) + (time.tv_usec/1000.0);
		//Wait for reponse
		pollfd readset;
   		readset.fd = UDPsock;
		readset.events = 0;
   		retval = poll(&readset, 1, 2000);
		//Check results
		if (retval < 0) {
   			perror("poll()");
			return -1;
		}
		else if (retval == 0) {
			printf("%d  *\n", ttl);
			close(UDPsock);
			continue;
		}
		//---------------------------------------
		char buffer[REQ_DATASIZE];
		struct iovec iov;      /* Data array */
		struct msghdr message; /* Message header */
		struct icmphdr icmph;  /* ICMP header */
		struct sockaddr_storage their_addr;

		iov.iov_base = &icmph;
		iov.iov_len = sizeof(icmph);
		message.msg_name = &their_addr;
		message.msg_namelen = sizeof(struct sockaddr_in);
		message.msg_iov = &iov;
		message.msg_iovlen = 1;
		message.msg_flags = 0;
		message.msg_control = buffer;
		message.msg_controllen = sizeof(buffer);

		retval = recvmsg(UDPsock, &message, MSG_ERRQUEUE);
		if (retval < 0) {
			perror("recvmsg");
			return -1;
		}
		if (retval == 0) {
			printf("%d  %s  *\n", ttl, addrToString(&their_addr).c_str());
			continue;
		}

		//Get time
		gettimeofday(&time, NULL);
		double to = (time.tv_sec * 1000.0) + (time.tv_usec / 1000.0);
		int code;
		//-----------------------------------------
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
			cmsg;
			cmsg = CMSG_NXTHDR(&message, cmsg))
		{
			code = getResponse(cmsg, &their_addr);
			if (code == -1) {
            	perror("icmp");
                break;
            }
			//Error handling
			int retval = ICMPerrHandling(code, cmsg, conf.mod6);
			if (retval == -1) {
				done = true;
				break;
			}
		}
        printf("%d  %s  %0.3fms\n", ttl, addrToString(&their_addr).c_str(), 
				to - from);
		close(UDPsock);
	} while (ttl < conf.max_ttl && !done);
	freeaddrinfo(conn);
}

int checkArgs(int argc, char **argv, Config *conf) {
	int fttl = 1;
	int mttl = 30;
	string ip_addr;
	int c;
	while ((c = getopt (argc, argv, "f:m:")) != -1)
		switch (c) {
			case 'f':
        		fttl = atoi(optarg);
        		break;
      		case 'm':
        		mttl = atoi(optarg);
        		break;
    	  	case '?':
        		if (optopt == 'f' || optopt == 'm')
          			fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        		else if (isprint (optopt))
          			fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        		else
          			fprintf(stderr, "Unknown option character `\\x%x'.\n",
                   			optopt);
			return -1;
      		default:
        		abort ();
	}
	conf->first_ttl = fttl;
	conf->max_ttl = mttl;
	if (argv[optind] != NULL) {
		conf->ip_addr = argv[optind];
		//Determine if the IPv4 or IPv5 address was provided	
		struct sockaddr_in6 tmp;
		if ((inet_pton(AF_INET, conf->ip_addr.c_str(), (void *)&tmp.sin6_addr)) == 1)
			conf->mod6 = false;
		else if ((inet_pton(AF_INET6, conf->ip_addr.c_str(), (void *)&tmp.sin6_addr)) == 1)
			conf->mod6 = true;
		else {
			fprintf(stderr, "Bad format of IP address - only IPv4/IPv6 addresses allowed.\n");
			return -1;
		}
	}
	else {
		fprintf(stderr, "No required option: ip_addr (man trace for more details)\n");
		return -1;
	}
	//--------------------------------
	if (conf->mod6) cout << "IPv6 ";
	else cout << "IPv4 ";
	cout << conf->ip_addr << '\n';
	return 0;
	//----------------------------------
}

int createUDPSocket(int ttl, bool mod6) {
	//Create a UDP socket
	int af, ip, iperr, ipttl;
	if (mod6) {
		af = AF_INET6;
		ip = SOL_IPV6;
		iperr = IPV6_RECVERR;
		ipttl = IPV6_UNICAST_HOPS;
	}
	else {
		af = AF_INET;
		ip = IPPROTO_IP;
		iperr = IP_RECVERR;
		ipttl = IP_TTL;
	}
	int sock = socket(af, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1) {
    		perror("Socket error");
		return -1;
	}
	if (setsockopt(sock, ip, ipttl, &ttl, sizeof ttl)) {
                perror("setsockopt:");
                return -1;
	}
	int x = 1;
	if (setsockopt(sock, ip, iperr, &x, sizeof x)) {
                perror("setsockopt:");
                return -1;
        }
	return sock;
}

int sendPing(int sock, struct addrinfo *connection) {
	char message[REQ_DATASIZE];
	memset(message, ' ', REQ_DATASIZE);
	int bytes = sendto(sock, message, sizeof message, 0, connection->ai_addr, connection->ai_addrlen);
	if (bytes == -1) {
		perror("Send error");
		return -1;
	}
	return bytes;
}

struct addrinfo* connectionSetup(string dest, bool mod6) {
	struct addrinfo exp, *connection;
    exp.ai_family = mod6 ? AF_INET6 : AF_INET;
	memset(&exp, 0, sizeof exp);
    int ret = getaddrinfo(dest.c_str(), "33435", &exp, &connection);
    if (ret != 0) {
    	printf("%s\n", gai_strerror(ret));
		return NULL;
	}
	return connection;
}

void cleanup(int sock, struct addrinfo *conn) {
	close(sock);
        freeaddrinfo(conn);
}

int getResponse(struct cmsghdr *cmsg, struct sockaddr_storage *addr_p) {
	struct sock_extended_err *sock_err;
	sock_err = (struct sock_extended_err *)CMSG_DATA(cmsg);
	if (sock_err) {
		if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP) {
			*addr_p = *(struct sockaddr_storage *)SO_EE_OFFENDER(sock_err);
			return sock_err->ee_type;
		}
	}
	return 0;
}

void printICMPerr(int code, bool mod6) {
	if (mod6) {
		switch (code) {
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			cout << "H!";
			break;
		case ICMP6_DST_UNREACH_NOROUTE:
			cout << "N!";
			break;
		case ICMP6_DST_UNREACH_ADDR:
			cout << "P!";
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			cout << "X!";
			break;
		default:
			break;
		}
	}
	else {
		switch (code) {
		case ICMP_HOST_UNREACH:
			cout << "H!";
			break;
		case ICMP_NET_UNREACH:
			cout << "N!";
			break;
		case ICMP_PROT_UNREACH:
			cout << "P!";
			break;
		case ICMP_PKT_FILTERED:
			cout << "X!";
			break;
		default:
			break;
		}
	}
}

int ICMPerrHandling(int code, struct cmsghdr *cmsg, bool mod6) {
	int level = mod6 ? SOL_IPV6 : SOL_IP;
	int type = mod6 ? IPV6_RECVERR : IP_RECVERR;
	int code_unreach = mod6 ? ICMP6_DST_UNREACH : ICMP_DEST_UNREACH;
	if (cmsg->cmsg_level == level && cmsg->cmsg_type == type) {   
		printICMPerr(code, mod6);
		if (code == code_unreach)
			return -1;
	}
	return 0;
}

void *getaddr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	} else {
		return &(((struct sockaddr_in6*)sa)->sin6_addr);
	}
}

string addrToString(struct sockaddr_storage *addr)
{
	char s[INET6_ADDRSTRLEN];
	const void *dst = inet_ntop(
		addr->ss_family,
		getaddr((struct sockaddr *)addr),
		s,
		sizeof s
	);	
	if (dst == NULL) {
		perror("inet_ntop");
	}	
	return string(s);
}
