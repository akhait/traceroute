#include <stdlib.h>
#include <string>

struct Config {
    int first_ttl;
    int max_ttl;
    std::string ip_addr;
	bool mod6;
};

int checkArgs(int argc, char **argv, Config *conf);
int createUDPSocket(int ttl, bool mod6);
int sendPing(int sock, struct addrinfo *connection);
struct addrinfo* connectionSetup(std::string dest, bool mod6);
int getResponse(struct cmsghdr *cmsg, struct sockaddr_storage *addr_p);
void printICMPerr(int code, bool mod6);
int ICMPerrHandling(int code, struct cmsghdr *cmsg, bool mod6);
void *getaddr(struct sockaddr *sa);
std::string addrToString(struct sockaddr_storage *addr);
