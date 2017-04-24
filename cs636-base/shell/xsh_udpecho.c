/* xsh_udpecho.c - xsh_udpecho */

#include <xinu.h>
#include <stdio.h>
#include <string.h>

static byte	buf[56];			/* buffer of chars		*/
static char eofReceived = 0;			/* Flag for EOF */

static uint32 tSentudp = 0;
uint32 tRecvudp = 0;

static void sender(int32 slot, char* msg, int32 msglen)	{
	intmask mask;
	mask = disable();
	tSentudp = hpet->mcv_l;
	restore(mask);
	udp_send(slot, msg, msglen);
	//ip6addr_print(ipaddr);
}


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
 * xsh_udpecho - shell command that can send a message to a remote UDP
 *			echo server and receive a reply
 *------------------------------------------------------------------------
 */
shellcmd xsh_udpecho(int nargs, char *args[])
{

	int	i=0;			/* index into buffer		*/
	int	retval;			/* return value			*/
	char	msg[] = "Xinu"; /* message to send	*/
	char	inbuf[1500];		/* buffer for incoming reply	*/
	int32	slot;			/* UDP slot to use		*/
	int32	msglen;			/* length of outgoing message	*/
	byte	remoteip[16];		/* remote IP address to use	*/
	//uint32	localip;		/* local IP address to use	*/
	uint16	echoport= 7;		/* port number for UDP echo	*/
	uint16	locport	= 52743;	/* local port to use		*/
	int32	retries	= 20;		/* number of retries		*/
	int32	delay	= 1000;		/* reception delay in ms	*/
	int32 pSent = 0, pRecv = 0;



	int32 iface = 0;                  /* Interface number */
	/* For argument '--help', emit help about the 'udpecho' command	*/

	if (nargs == 2 && strncmp(args[1], "--help", 7) == 0) {
		printf("Use: %s  REMOTEIP\n\n", args[0]);
		printf("Description:\n");
		printf("\tBounce a message off a remote UDP echo server\n");
		printf("Options:\n");
		printf("\tREMOTEIP:\tIP address in dotted decimal\n");
		printf("\t--help\t display this help and exit\n");
		return 0;
	}

	/* Check for valid IP address argument */

	if (nargs != 3) {
		fprintf(stderr, "%s: invalid argument(s)\n", args[0]);
		fprintf(stderr, "Try '%s --help' for more information\n",
				args[0]);
		return 1;
	}

     if(nargs == 3)
     {
	if(args[2][0] == '0')
	{
		iface = 0;

	}
	else if(args[2][0] == '1')
	{
		iface = 1;

	}
	else if(args[2][0] == '2') 
	{
		iface = 2;
	}

     }
	
	/*if (dot2ip(args[1], &remoteip) == SYSERR) {
		fprintf(stderr, "%s: invalid IP address argument\r\n",
			args[0]);
		return 1;
	}*/
	if(hex2ip(args[1], remoteip) == SYSERR){
		kprintf("\nIP Address couldn't be processed!\n");
		return 1;
	}
	/* register local UDP port */


	slot = udp_register(iface, remoteip, echoport, locport);
	if (slot == SYSERR) {
		fprintf(stderr, "%s: could not reserve UDP port %d\n",
				args[0], locport);
		return 1;
	}

	/* Retry sending outgoing datagram and getting response */
	resume(create(pollInputEof, 1024, 60, "Poller", 0, 0));
	msglen = strnlen(msg, 1200);
	while(eofReceived == 0)	{

		retval = resume(create(sender, 4096, 60, "Sender", 3, slot, msg, msglen));
		if (retval == SYSERR) {
			fprintf(stderr, "%s: error sending UDP \n",
				args[0]);
			return 1;
		}
		//kprintf("UDP sent\n");
		pSent++;
		retval = udp_recv(slot, inbuf, sizeof(inbuf), delay);
		if (retval == TIMEOUT) {
			fprintf(stderr, "%s: timeout...\n", args[0]);
			continue;
		} else if (retval == SYSERR) {
			fprintf(stderr, "%s: error from udp_recv \n",
				args[0]);
			//udp_release(slot);
			return 1;
		}
		//break;
		pRecv++;
		
		kprintf("UDP Datagram %d received with rtt = %.6fms \n", pRecv, ((tRecvudp - tSentudp )/14318.0));		
		sleepms(1000);
	}
	eofReceived = 0;
	udp_release(slot);
	if (retval == TIMEOUT) {
		fprintf(stderr, "%s: retry limit exceeded\n",
			args[0]);
		return 1;
	}

	/* Response received - check contents */


kprintf("--- UDP ping statistics ---\n");
	kprintf("%d packets transmitted, %d received, %d%% packet loss, time %dms\n", pSent,pRecv,(((pSent-pRecv)*100)/pSent),0);


	return 0;
}
