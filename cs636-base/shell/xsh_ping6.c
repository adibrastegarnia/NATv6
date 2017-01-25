/* xsh_ping.c - xsh_ping */

#include <xinu.h>
#include <stdio.h>
#include <string.h>

/*------------------------------------------------------------------------
 * xsh_ping - shell command to ping a remote host
 *------------------------------------------------------------------------
 */
shellcmd xsh_ping6(int nargs, char *args[])
{

	byte	ipaddr[16];			/* IP address in binary		*/
	/* For argument '--help', emit help about the 'ping' command	*/

	if (nargs == 2 && strncmp(args[1], "--help", 7) == 0) {
		printf("Use: %s  address\n\n", args[0]);
		printf("Description:\n");
		printf("\tUse ICMP Echo to ping a remote host\n");
		printf("Options:\n");
		printf("\t--help\t display this help and exit\n");
		printf("\taddress\t an IP address in dotted decimal\n");
		return 0;
	}

	/* Check for valid number of arguments */

	if (nargs != 2) {
		fprintf(stderr, "%s: invalid arguments\n", args[0]);
		fprintf(stderr, "Try '%s --help' for more information\n",
				args[0]);
		return 1;
	}


	hex2ip(args[1], ipaddr);
	icmp6_send(ipaddr, ICMP6_ECHREQ_TYPE, 0, (void *)data, 100,0);

	
}


