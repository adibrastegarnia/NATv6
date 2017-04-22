#include <xinu.h>

struct	icmpentry icmptab[ICMP_SLOTS];   /* Table of processes using ping*/

extern uint32 tRecv;


/*--------------------------------------------------------------
 * icmp_init: Initialize icmp table 
 * -------------------------------------------------------------*/

void icmp_init(void){

	
	int32 i;	/* Table index */

	for(i=0; i < ICMP_SLOTS; i++)
	{

		icmptab[i].icstate = ICMP_FREE;
	}

	

	return;

}


/*--------------------------------------------------------------
 * icmp_in: Handle incoming icmp packet
 * -----------------------------------------------------------*/

void icmp6_in(struct netpacket *pktptr)
{
	intmask	mask;			/* Saved interrupt mask		*/
	int32	slot;			/* Slot in ICMP table		*/
	struct	icmpentry *icmptr;	/* Pointer to icmptab entry	*/

	if(icmp6_chksum(pktptr) !=0)
	{
		kprintf("net_ictype %d\n", pktptr->net_ictype);
		kprintf("Checksum is failed\n");
		ip6addr_print(pktptr->net_ip6src);
		ip6addr_print(pktptr->net_ip6dst);
		return;

	}
	/* Check ICMPv6 message type */
	kprintf("net_ictype %d\n", pktptr->net_ictype);
	switch(pktptr->net_ictype)
	{
		
		/* ICMP Echo request */
		case ICMP6_ECHREQ_TYPE:
			kprintf("ICMP Echo request\n");
			icmp6_send(pktptr->net_ip6src, 
					ICMP6_ECHRES_TYPE, 0,
					pktptr->net_icdata,
					pktptr->net_ip6len - 4, 
					pktptr->net_iface);
			break;

		case ICMP6_ECHRES_TYPE:kprintf("ICMP Echo response\n");

			/* Handle Echo Reply message: verify that ID is valid */
			mask = disable();
			tRecv = hpet->mcv_l;
			slot = (int32)pktptr->net_icmpseqno;
			if ( (slot < 0) || (slot >= ICMP_SLOTS) ) {
				freebuf((char *)pktptr);
				restore(mask);
				return;
			}
			/* Verify that slot in table is in use and IP address	*/
			/*    in incomming packet matches IP address in table	*/
			icmptr = &icmptab[slot];
			if ( (icmptr->icstate == ICMP_FREE) ) {
				freebuf((char *)pktptr);	/* discard packet */
				restore(mask);
				return;
			}
			/* Add packet to queue */
			icmptr->iccount++;
			icmptr->icqueue[icmptr->ictail++] = pktptr;
			if (icmptr->ictail >= ICMP_QSIZ) {
				icmptr->ictail = 0;
			}
			if (icmptr->icstate == ICMP_RECV) {
				icmptr->icstate = ICMP_USED;
				send (icmptr->icpid, OK);
			}
			restore(mask);
			break;
		/* ICMP Router Advertisement Message */
		case ICMP6_RAM_TYPE:
			//kprintf("ICMP6 Router Advertisemet message\n");
			nd_in(pktptr);
			break;
		/* ICMP Router Solicitation Message */
		case ICMP6_RSM_TYPE:
			//kprintf("ICMP6 Router solicitation message\n");
			nd_in(pktptr);
			break;

		/* ICMP Neighbour Soliciation Message */
		case ICMP6_NSM_TYPE:
			//kprintf("ICMP6 Neighbor Solicitation message\n");
			nd_in(pktptr);
			break;

		/* ICMP Neighbour Advertisment Message */
		case ICMP6_NAM_TYPE:
			//kprintf("ICMP6 neighbor Advertisment message\n");
			nd_in(pktptr);
			break;
		default:
			kprintf("Unknown ICMP type:%d", pktptr->net_ictype);
	}


}


struct netpacket *icmp_mkpkt(byte remip[], 
		byte ictype, 
		byte iccode, 
		void *icdata, 
		int32 datalen, 
		int32 iface){

	
	struct ifentry   *ifptr;
	struct netpacket *pkt;

	intmask mask;
	mask = disable();
	/* Allocate buffer from netbufpool */
	pkt = (struct netpacket *)getbuf(netbufpool);

	if ((int32)pkt == SYSERR) {
		panic("icmp_mkpkt: cannot get a network buffer\n");
	}
	
	
	/* Initialize packet to zeros 		*/
	memset(pkt, 0 , sizeof(struct netpacket));


	pkt->net_iface = iface; 
	pkt->net_ip6ver = 0x60;     /* IPv6 		*/ 
	pkt->net_ip6nh = IP_ICMP6;  /* ICMPv6 Packet    */
	pkt->net_ip6hl = 255;       
	pkt->net_ip6len = 4 + datalen;
	memcpy(pkt->net_ip6dst, remip, 16);
kprintf("Mkpt:");
ip6addr_print(remip);
        ifptr = &if_tab[iface];

	if(isipula(remip))
	{

		memcpy(pkt->net_ip6src, ifptr->if_ip6ucast[1].ip6addr, 16);

	}
	else if(isipmc(remip))
	{



			memcpy(pkt->net_ip6src, ifptr->if_ip6ucast[0].ip6addr, 16);
		

	}


	else if(isipllu(remip))
	{
		memcpy(pkt->net_ip6src, ifptr->if_ip6ucast[0].ip6addr, 16);

	}
	//kprintf("ICTYPE %d\n", ictype);
	pkt->net_ictype = ictype;
	pkt->net_iccode = iccode;
	pkt->net_icchksm = 0x0000;
	memcpy(pkt->net_icdata, icdata, datalen);

	
	/* return packet to the caller */

	restore(mask);
	return pkt;

}
/*--------------------------------------------------------------
 * icmp_send: Send an icmp packet 
 * ------------------------------------------------------------*/

status icmp6_send(byte remip[], 
		byte ictype, 
		byte iccode, 
		void *icdata,
		int32 datalen,
		int32 iface){

	
	intmask mask;
	struct netpacket *pkt;
	int32 retval;
	/* Disable intruptts */
	mask = disable();
	/* Create an ICMPv6 packet */
//ip6addr_print(remip);

	pkt = icmp_mkpkt(remip, ictype, iccode, icdata, datalen, iface);
        if((int32)pkt == SYSERR)
	{
		return SYSERR;

	}
//	kprintf("Send ICMP message: \n");
//ip6addr_print(pkt->net_ip6src);
//ip6addr_print(pkt->net_ip6dst);
	/* Send ICMPv6 packet */
	retval = ip6_send(pkt);
	restore(mask);

	return retval;

}

/*-------------------------------------------------------------
 * icmp6_chksum: Compute ICMPv6 checksum 
 * -----------------------------------------------------------*/

uint16 icmp6_chksum(struct netpacket *pktptr)
{
	
	uint32 checksum = 0;

	int i = 0;
	uint16 *ptr16;
	struct pseudo pseudo_hdr;
	memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));
	memcpy(pseudo_hdr.ip6_src, pktptr->net_ip6src, 16);
	memcpy(pseudo_hdr.ip6_dst, pktptr->net_ip6dst, 16);
	pseudo_hdr.pktlen = htonl(pktptr->net_ip6len);
	pseudo_hdr.ipnh = IP6_EXT_ICMP;

	ptr16 = (uint16 *)&pseudo_hdr;

	for(i = 0; i < sizeof(pseudo_hdr); i = i + 2) {
		checksum = checksum + htons(*ptr16);
		ptr16++;

	}

	ptr16 = (uint16 *)pktptr->net_ipdata;

	for(i = 0; i < pktptr->net_ip6len; i = i + 2) {
		checksum = checksum + htons(*ptr16);
		ptr16++;
	}

	checksum = (uint16)checksum + (checksum >> 16);
	//kprintf("chksum %d:%d\n", (uint16)(checksum), (uint16)(~checksum));
	return (uint16)~checksum;


}



/*------------------------------------------------------------------------
 * icmp_register  -  Register a remote IP address for ping replies
 *------------------------------------------------------------------------
 */
int32	icmp6_register (
	 byte	remip[]			/* Remote IP address		*/
	)
{
	intmask	mask;			/* Saved interrupt mask		*/
	int32	i;			/* Index into icmptab		*/
	int32	freeslot;		/* Index of slot to use		*/
	struct	icmpentry *icmptr;	/* Pointer to icmptab entry	*/

	mask = disable();

	/* Find a free slot in the table */

	freeslot = -1;
	for (i=0; i<ICMP_SLOTS; i++) {
		icmptr = &icmptab[i];
		if (icmptr->icstate == ICMP_FREE) {
			if (freeslot == -1) {
				freeslot = i;
			}
		} else if (memcmp(icmptr->icremip,remip,16) == 0) {
			restore(mask);
			return SYSERR;	/* Already registered */
		}
	}
	if (freeslot == -1) {  /* No free entries in table */

		restore(mask);
		return SYSERR;
	}

	/* Fill in table entry */

	icmptr = &icmptab[freeslot];
	icmptr->icstate = ICMP_USED;
	memcpy(icmptr->icremip, remip, 16);
	icmptr->iccount = 0;
	icmptr->ichead = icmptr->ictail = 0;
	icmptr->icpid = -1;
	restore(mask);
	return freeslot;
}

/*------------------------------------------------------------------------
 * icmp_recv  -  Receive an icmp echo reply packet
 *------------------------------------------------------------------------
 */
int32	icmp6_recv (
	 int32	icmpid,			/* ICMP slot identifier		*/
	 char   *buff,			/* Buffer to ICMP data		*/
	 int32	len,			/* Length of buffer		*/
	 uint32	timeout			/* Time to wait in msec		*/
	)
{
	intmask	mask;			/* Saved interrupt mask		*/
	struct	icmpentry *icmptr;	/* Pointer to icmptab entry	*/
	umsg32	msg;			/* Message from recvtime()	*/
	struct	netpacket *pkt;		/* Pointer to packet being read	*/
	int32	datalen;		/* Length of ICMP data area	*/
	char	*icdataptr;		/* Pointer to icmp data		*/
	int32	i;			/* Counter for data copy	*/

	/* Verify that the ID is valid */

	if ( (icmpid < 0) || (icmpid >= ICMP_SLOTS) ) {
		return SYSERR;
	}

	/* Insure only one process touches the table at a time */

	mask = disable();

	/* Verify that the ID has been registered and is idle */

	icmptr = &icmptab[icmpid];
	if (icmptr->icstate != ICMP_USED) {
		restore(mask);
		return SYSERR;
	}

	if (icmptr->iccount == 0) {		/* No packet is waiting */
		icmptr->icstate = ICMP_RECV;
		icmptr->icpid = currpid;
		msg = recvclr();
		msg = recvtime(timeout);	/* Wait for a reply */
		icmptr->icstate = ICMP_USED;
		if (msg == TIMEOUT) {
			restore(mask);
			return TIMEOUT;
		} else if (msg != OK) {
			restore(mask);
			return SYSERR;
		}
	}

	/* Packet has arrived -- dequeue it */

	pkt = icmptr->icqueue[icmptr->ichead++];
	if (icmptr->ichead >= ICMP_QSIZ) {
		icmptr->ichead = 0;
	}
	icmptr->iccount--;

	/* Copy data from ICMP message into caller's buffer */

	datalen = pkt->net_ip6len - IP_HDR_LEN - ICMP_HDR_LEN;
	icdataptr = (char *) &pkt->net_icdata;
	for (i=0; i<datalen; i++) {
		if (i >= len) {
			break;
		}
		*buff++ = *icdataptr++;
	}
	freebuf((char *)pkt);
	restore(mask);
	return i;
}


/*------------------------------------------------------------------------
 * icmp_release  -  Release a previously-registered ICMP icmpid
 *------------------------------------------------------------------------
 */
status	icmp6_release (
	 int32	icmpid			/* Slot in icmptab to release	*/
	)
{
	intmask	mask;			/* Saved interrupt mask		*/
	struct	icmpentry *icmptr;	/* Pointer to icmptab entry	*/
	struct	netpacket *pkt;		/* Pointer to packet		*/

	mask = disable();

	/* Check arg and insure entry in table is in use */

	if ( (icmpid < 0) || (icmpid >= ICMP_SLOTS) ) {
		restore(mask);
		return SYSERR;
	}
	icmptr = &icmptab[icmpid];
	if (icmptr->icstate != ICMP_USED) {
		restore(mask);
		return SYSERR;
	}

	/* Remove each packet from the queue and free the buffer */

	resched_cntl(DEFER_START);
	while (icmptr->iccount > 0) {
		pkt = icmptr->icqueue[icmptr->ichead++];
		if (icmptr->ichead >= ICMP_SLOTS) {
			icmptr->ichead = 0;

		}
		freebuf((char *)pkt);
		icmptr->iccount--;
	}

	/* Mark the entry free */

	icmptr->icstate = ICMP_FREE;
	resched_cntl(DEFER_STOP);
	restore(mask);
	return OK;
}



