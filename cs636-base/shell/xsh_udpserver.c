/* xsh_udpeserver.c - xsh_udpeserver */

#include <xinu.h>
#include <stdio.h>
#include <string.h>


static char eofReceived = 0;			/* Flag for EOF */


static void pollInputEof()	{
	char nextch;
	nextch = getc(stdin);
	while (nextch != EOF) {
		putc(stdout, nextch);
		nextch = getc(stdin);
	}
	eofReceived = 1;
}
/*------------------------------------------------------------------------
 * xsh_udpeserver - shell command that acts as a UDP echo server (is
 *			usually run in background)
 *------------------------------------------------------------------------
 */
shellcmd xsh_udpeserver(int nargs, char *args[])
{

	int32	retval;			/* return value from sys calls	*/
	uint16	remport = 52743 ;		/* remote sender's UDP port	*/
	char	buff[1500];		/* buffer for incoming reply	*/
	int32	msglen;			/* length of outgoing message	*/
	int32	slot;			/* slot in UDP table 		*/
	uint16	echoserverport= 7;	/* port number for UDP echo	*/

	byte remoteip[]= {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	                  0, 0, 0};
	int32 iface = 0;
	/* For argument '--help', emit a help message	*/

	struct ipinfo ipdata;
	if (nargs == 2 && strncmp(args[1], "--help", 7) == 0) {
		printf("Use: %s\n\n", args[0]);
		printf("Description:\n");
		printf("\tBecome a UDP echo server\n");
		printf("Options:\n");
		printf("\t--help\t display this help and exit\n");
		return 0;
	}

	/* Check for valid IP address argument */

	if (nargs != 2) {
		fprintf(stderr, "%s: no arguments expected\n", args[0]);
		fprintf(stderr, "Try '%s --help' for more information\n",
				args[0]);
		return 1;
	}


	if(args[1][0] == '0')
	{
		iface = 0;

	}
	else if(args[1][0] == '1')
	{
		iface = 1;

	}
	else if(args[1][0] == '2') 
	{
		iface = 2;

	}

	/* register local UDP port */

	slot = udp_register(iface, remoteip, remport , echoserverport);
	if (slot == SYSERR) {
		fprintf(stderr, "%s: could not reserve UDP port %d\n",
				args[0], echoserverport);
		return 1;
	}

	/* Do forever: read an incoming datagram and send it back */

	int i=0;
	for(i=0; i< 16; i++)
	{
		ipdata.ip6src[i] = 0x00;
		ipdata.ip6dst[i] = 0x00;

	}
	ipdata.port = 52743;
resume(create(pollInputEof, 1024, 60, "Poller", 0, 0));

	while(eofReceived == 0)	{

		retval = udp_recvaddr(slot, buff, sizeof(buff), 600000, (struct ipinfo *)&ipdata);

		if (retval == TIMEOUT) {
			continue;
		} else if (retval == SYSERR) {
			fprintf(stderr, "%s: error receiving UDP\n",
				args[0]);
			return 1;
		}
		msglen = retval;
	

		retval = udp_sendto(slot, ipdata.ip6src, remport, buff, msglen);
		if (retval == SYSERR) {
			fprintf(stderr, "%s: udp_sendto failed\n",
				args[0]);
			return 1;
		}
		
	}
	eofReceived = 0;
	udp_release(slot);
	return 0;
}
