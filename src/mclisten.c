#include <sys/select.h>

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

int
main(int argc, char **argv)
{
	struct sockaddr_in localaddr;
	struct ip_mreq mcChannel;
	const static int one = 1, port = 8889;
	int r, s;
	fd_set readfds;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		fprintf(stderr, "socket");
		exit(1);
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		fprintf(stderr, "setsockopt:SO_REUSEADDR");
		exit(1);
	}

	    /* Listen on a well-known port. */
	memset(&localaddr, 0, sizeof(localaddr));
	localaddr.sin_family = AF_INET;
	localaddr.sin_port = htons(port);
	localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(s, (struct sockaddr *)&localaddr, sizeof(localaddr))) {
		fprintf(stderr, "bind");
		exit(1);
	}

	mcChannel.imr_multiaddr.s_addr = inet_addr("226.1.1.1");
	mcChannel.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mcChannel, sizeof(mcChannel)) == -1) {
		fprintf(stderr, "setsockopt:IP_ADD_MEMBERSHIP");
		exit(1);
	}

	FD_SET(s, &readfds);

	while (1) {
		r = select(1, &readfds, NULL, NULL, NULL);
		if (r == -1) {
			fprintf(stderr, "select error\n");
			break;
		}
		if (r == 0) {
			fprintf(stderr, "nothing to do\n");
			continue;
		}
		fprintf(stderr, "got some data\n");
	}


	return (0);
}
