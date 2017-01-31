/* xsh_ping.c - xsh_ping */

#include <xinu.h>
#include <stdio.h>
#include <string.h>
char	buf[56];			/* buffer of chars		*/

void sender(byte* ipaddr, int32 interface)	{
	icmp6_send(ipaddr, ICMP6_ECHREQ_TYPE, 0, (void *)buf, 56,interface);
}
/*------------------------------------------------------------------------
 * xsh_ping - shell command to ping a remote host
 *------------------------------------------------------------------------
 */
shellcmd xsh_ping6(int nargs, char *args[])
{
	int32 pings = 5;
	byte	ipaddr[16];			/* IP address in binary		*/
	int32	retval;			/* return value			*/
	char	rbuf[56];			/* buffer of chars		*/
	int32	slot;				/* Slot in ICMP to use		*/
	int32	i;		/* next value to use		*/
	int32 pSent = 0, pRecv = 0;
	int32 iface = 0;
	struct	ifentry	*ifptr;		/* Ptr to interface table entry	*/
	static int32 seq = 0;

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

	if (nargs < 2) {
		fprintf(stderr, "%s: invalid arguments\n", args[0]);
		fprintf(stderr, "Try '%s --help' for more information\n",
				args[0]);
		return 1;
	}

	if(nargs == 3)	{
		if(args[2][0] == '0'){
				//iface already 0
			}
		else if(args[2][0] == '1'){
				iface = 1;
			}
		else if(args[2][0] == '2'){
				iface  = 2;
			}
		else	{
			kprintf("\n Unsupported Interface!\n");
			return 1;
		}
	}
	

	if(hex2ip(args[1], ipaddr) == SYSERR){
		kprintf("\nIP Address couldn't be processed!\n");
		return 1;
	}

	/* Register to receive an ICMP Echo Reply */
	ifptr = &if_tab[iface];
	slot = icmp6_register(ipaddr);
	if (slot == SYSERR) {
		fprintf(stderr,"%s: ICMP registration failed\n", args[0]);
		return 1;
	}

	/* Fill the buffer with values - start with low-order byte of	*/
	/*	the sequence number and increment			*/
	buf[0] = slot;
	buf[1] = ++seq;
	for (i = 2; i<sizeof(buf); i++) {
		buf[i] = 0xff & i;
	}
	


	kprintf("\n\n PING ");
	ip6addr_print(ipaddr);
 	kprintf("\n from ");
	ip6addr_print(ifptr->if_ip6ucast[0].ip6addr);
 	kprintf(" on interface %s with", ifptr->if_name);
 	kprintf(" 56 data bytes\n\n");

	while(pings--)	{
		kprintf("Pinging ..\n");
		//SET TIMER DATA
		//Update seq no
		buf[1] = ++seq;

		resume(create(sender, 1024, 60, "Sender", 2, ipaddr, iface));
		pSent++;
		// Receive and print packet data
		
		/* Read a reply */
		retval = icmp6_recv(slot, rbuf, sizeof(rbuf), 500);
		/*kprintf("Received seq = %d, slot = %d, sent seq = %d, slot =%d \n", rbuf[1], rbuf[0], seq, slot);
		for (i = 0; i<sizeof(rbuf); i++) {
			kprintf("%01x ",rbuf[i]);// = 0xff & i;
		}*/
		//GET TIMER DATA
		if (retval == TIMEOUT) {
			kprintf("ping6: no response from host %s\n", args[1]);
		}
		else{
			if(rbuf[1] == seq && rbuf[0] ==slot)	{
				pRecv++;		
				kprintf("%d bytes from ", 56);	
				ip6addr_print(ipaddr);
				kprintf(": rtt = %d \n",0);// time1-time2);
			}
			else{
				//kprintf("Received seq = %d, slot = %d, sent seq = %d, slot =%d", buf[1], buf[0], seq, slot);
			}
		}


		sleepms(1000);
	}
	icmp6_release(slot);
	// Ping statistics
	kprintf("--- ");ip6addr_print(ipaddr); kprintf("  ping statistics ---\n");
	kprintf("%d packets transmitted, %d received, %d%% packet loss, time %dms\n", pSent,pRecv,(((pSent-pRecv)*100)/pSent),0);
	kprintf("rtt min/avg/max/mdev = %f/%f/%f/%f ms\n\n", 0,0,0,0);


	return 0;
}


