#include <xinu.h>

struct	icmpentry icmptab[ICMP_SLOTS];   /* Table of processes using ping*/



/*---------------------------------------------------------------
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


	if(icmp6_chksum(pktptr) !=0)
	{

		kprintf("Checksum is failed\n");
		return;

	}
	/* Check ICMPv6 message type */
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

		/* ICMP Router Advertisement Message */
		case ICMP6_RAM_TYPE:
			kprintf("ICMP6 Router Advertisemet message\n");
			break;
		/* ICMP Router Solicitation Message */
		case ICMP6_RSM_TYPE:
			kprintf("ICMP6 Router solicitation message\n");
			break;

		/* ICMP Neighbour Soliciation Message */
		case ICMP6_NSM_TYPE:
			kprintf("ICMP6 Neighbor Solicitation message\n");
			nd_in(pktptr);
			break;

		/* ICMP Neighbour Advertisment Message */
		case ICMP6_NAM_TYPE:
			nd_in(pktptr);
			kprintf("ICMP6 neighbor Advertisment message\n");
			break;

	}


}


struct netpacket *icmp_mkpkt(byte remip[], 
		byte ictype, 
		byte iccode, 
		void *icdata, 
		int32 datalen, 
		int32 iface){

	
	struct netpacket *pkt;

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

	pkt->net_ictype = ictype;
	pkt->net_iccode = iccode;
	pkt->net_icchksm = 0x0000;
	memcpy(pkt->net_icdata, icdata, datalen);


	/* return packet to the caller */

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
	pkt = icmp_mkpkt(remip, ictype, iccode, icdata, datalen, iface);
        if((int32)pkt == SYSERR)
	{
		return SYSERR;

	}

	/* Send ICMPv6 packet */
	retval = ip6_send(pkt);
	restore(mask);

	return retval;

}

/*-------------------------------------------------------------
 * icmp6_chksum: Computer ICMPv6 checksum 
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




