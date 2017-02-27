#include <xinu.h>


struct	iqentry ipoqueue; 

/* Unique local address prefix */
byte ip6_ulapref[]= {0xfd, 0x00, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


/* IP Link-local prefix */
byte	ip6_llpref[] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0 };

/* Solicited-node Multicast prefix */
byte	ip6_nd_snmpref[] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 0xff, 0, 0, 0};


/* Unspecified IP address */
byte ip6_unspec[16] = {0};


/* All nodes IPv6 multicast address */
byte ip6_allnodesmc[] = { 0xff, 0x01, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1};;


/* All routers IPv6 multicast address */
byte ip6_allroutermc[]= { 0xff, 0x01, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 2};

/* ip6ula_gen: Generate a unique local IP address  */
void ip6ula_gen(int32 index, struct ifentry *ifptr)
{
	int32 index2 = ifptr->if_nipucast;

	memcpy(ifptr->if_ip6ucast[index2].ip6addr, ip6_ulapref, 16);
	ifptr->if_ip6ucast[index2].ip6addr[1] = index;

	memcpy(ifptr->if_ip6ucast[index2].ip6addr + 2, ifptr->if_macucast , ETH_ADDR_LEN - 2);
	ifptr->if_ip6ucast[index2].ip6addr[6] = index;
	ifptr->if_ip6ucast[index2].preflen = 2;
	ifptr->if_nipucast++;

	return;

}

/*----------------------------------------------
 * ip6llgen : Generate a link local IPv6 address 
 * --------------------------------------------*/
void ip6llgen(struct ifentry *ifptr)
{
	int32 index = ifptr->if_nipucast;
        /* Generate a link local IPv6 address */
	memcpy(ifptr->if_ip6ucast[index].ip6addr, ip6_llpref, 16);
	memcpy(ifptr->if_ip6ucast[index].ip6addr+8, ifptr->if_macucast, 3);
	ifptr->if_ip6ucast[index].ip6addr[11] = 0xff;
	ifptr->if_ip6ucast[index].ip6addr[12] = 0xfe;
	memcpy(ifptr->if_ip6ucast[index].ip6addr+13, ifptr->if_macucast+3, 3);

	if(ifptr->if_macucast[0] & 0x02) {
		ifptr->if_ip6ucast[index].ip6addr[8] &= 0xfd;

	}
	else
	{
		ifptr->if_ip6ucast[index].ip6addr[8] |= 0x02;

	}
	ifptr->if_nipucast++;
}

/* -------------------------------------------------------------
 * ip6_snmaddrgen: Generate a solicited-node multicast address 
 -------------------------------------------------------------*/

status ip6_snmaddrgen(int32 inducast, struct ifentry *ifptr)
{

	int index = ifptr->if_nipmcast;
	
	memcpy(ifptr->if_ip6mcast[index].ip6addr, ip6_nd_snmpref, 16);
	memcpy(ifptr->if_ip6mcast[index].ip6addr + 13, ifptr->if_ip6ucast[inducast].ip6addr +13, 3);
	//ip6addr_print(ifptr->if_ip6mcast[index].ip6addr);

	ifptr->if_nipmcast++;
	return OK;

}

/* -----------------------------------------------------------------
 * ip6_nwmcast_gen: Retrive Ethernet multicast address used by ND 
 * ---------------------------------------------------------------*/

status ip6_nwmcast_gen(int32 indmcast, struct ifentry *ifptr)
{
	
	ifptr->if_ip6newmcast[indmcast].if_ip6nwmcast[0] = 0x33;
	ifptr->if_ip6newmcast[indmcast].if_ip6nwmcast[1] = 0x33;
	memcpy(ifptr->if_ip6newmcast[indmcast].if_ip6nwmcast + 2, ifptr->if_ip6mcast[indmcast].ip6addr + 12, 4);

	return OK;
}

/* ip6_mcrouter: Generate all router multicast address */
status ip6_mcrouter_gen(struct ifentry *ifptr)
{
	int index = ifptr->if_nipmcast;
	memcpy(ifptr->if_ip6mcast[index].ip6addr, ip6_allroutermc, 16);
	ifptr->if_nipmcast++;
	return OK;

}




/* -------------------------------------------------------
 * Handle an IPv6 packet that has arrived over a network *
 * -------------------------------------------------------*/
void ip6_in(struct netpacket *pktptr)
{

	intmask mask;
	int i;
	struct	ifentry *ifptr; 	/* Network interface pointer	*/

        mask = disable();
	ip6_ntoh(pktptr);

	/* Check IPv6 version */
	if(((pktptr->net_ip6ver) & 0xf0) != 0x60)
	{
		kprintf("IP version failed\n\r");
		freebuf((char *)pktptr);
		return;

	}

	
	
	/* Check the interface is valid or not */
	if(pktptr->net_iface < 0 || pktptr->net_iface > NIFACES)
	{
		kprintf("Invalid interface number %d\n", pktptr->net_iface);
		return;

	}



	ip6addr_print(pktptr->net_ip6dst);kprintf(" is IP_IN dest addr");
	ifptr = &if_tab[pktptr->net_iface];

	/* Match IPv6 destination address with our unicast, multicast address, or ULA */
	if(!isipmc(pktptr->net_ip6dst))
	{
		if(host)
		{
			for(i=0; i < ifptr->if_nipucast; i++)
			{
				/* Compare our IPv6 unicast address with packet destination address */
				if(!memcmp(pktptr->net_ip6dst, ifptr->if_ip6ucast[i].ip6addr, 16))
				{
				//kprintf("found ip for host\n");
				//ip6addr_print(pktptr->net_ip6dst);
				break;
				}
				if(i >= ifptr->if_nipucast)
				{kprintf("dest ip not found\n");
					restore(mask);
					return;
				}
			}
		}
		else
		{

			nat_in(pktptr);
			restore(mask);
			return;


		}
	}
	else
	{
		for(i=0; i < ifptr->if_nipmcast; i++)
		{
			/* Compare our IPv6 Multicast address with packet destionation address */
			if(!memcmp(pktptr->net_ip6dst, ifptr->if_ip6mcast[i].ip6addr, 16))
			{
				break;

			}

		}
		if(i >= ifptr->if_nipmcast)
		{
		
			restore(mask);
			return;

		}

	}


	/* Process the extension headers */
	
	ip6_in_ext((struct netpacket *)pktptr);
	restore(mask);
	return;

	
}

/*----------------------------------------------------------------
 * ip6-in_ext: Process the extension headers for the IPv6 packet
----------------------------------------------------------------*/

void ip6_in_ext(struct netpacket *pktptr)
{
	//struct ifentry *ifptr;
	//struct ip6_ext_hdr *exptr;
	byte nh_value;

	/* Get the interface pointer */
	//ifptr = &if_tab[pktptr->net_iface];



	/* Get Next header value */
	nh_value = pktptr->net_ip6nh;

	//exptr = (struct ip6_ext_hdr *)pktptr->net_ipdata;

	while(nh_value != IP6_EXT_NOHDR)
	{
               	//kprintf("Next header value %d\n", nh_value);

		switch(nh_value)
		{
			case IP6_EXT_HBH:
				kprintf("Hop by Hop header\n");
				return;

			case IP6_EXT_ICMP:
				kprintf("ICMP IN\n");
				icmp6_in(pktptr);
				return;
			default:
				kprintf("Unknown IP next header: %02d. Discarding packet\n", nh_value);	

		}
		//nh_value = exptr->ip6ext_nh;
		//exptr = (struct ip6_ext_hdr *)((char *)exptr + 8 + exptr->ip6ext_len * 8);

	}

	



	return;
}

/* ----------------------------------------------------------
 * ip6addr_reso:  Resolve an IPv6 address to a Link layer address 
 * ---------------------------------------------------------*/
status ip6addr_reso(struct netpacket *pktptr)
{

	byte ipdst[16];
	int32 i;
	memcpy(ipdst, pktptr->net_ip6dst, 16);
        
	//ip6addr_print(pktptr->net_ip6dst);
	if(isipmc(ipdst))
	{

		//kprintf("Address Resoultion can not be performed on Multicast Adddress");
		return -2;
	}
	struct nd_nbcentry *nbcptr;
	for(i=0; i < ND_NCACHE_SIZE;i++)
	{
		nbcptr = &nbcache_tab[i];
		if((memcmp(nbcptr->nc_nbipucast, ipdst, 16)) == 0)
		{		
			break;
		}

	}

	if(i >= ND_NCACHE_SIZE)
	{
		return SYSERR;

	}
	return i;

}

status ip6_route(struct netpacket *pktptr, byte nxthop[16])
{
	int32 i;

	int32 ncindex;
	int32 preflen;
	struct nd_routertbl *rtblptr;

	uint32 iplen;

	//struct ifentry  *ifptr; 
	struct nd_nbcentry *nbcptr;

	struct ifentry *ifptr;

	ifptr = &if_tab[ifprime];
	/* Check the destination address is Unique local address */
	if(isipula(pktptr->net_ip6dst))
	{

		/* Destination host is in the same subnet of the current host */
		//TODO: Check if this check i theoretically correct: practically is correct
		/*if((ifprime  == pktptr->net_ip6dst[6]) || (!host))
		{*/
			memcpy(nxthop, pktptr->net_ip6dst, 16);


			return;
		//}
		/* Destination host is not in the same subnet */

	}


	if(isipmc(pktptr->net_ip6dst))
	{

	        memcpy(nxthop, pktptr->net_ip6dst, 16);


		return OK;

	}

	if(isipllu(pktptr->net_ip6dst))
	{

		memcpy(nxthop, pktptr->net_ip6dst, 16);

		return OK;

	}

	kprintf("ip route is called\n");
	//ip6addr_print(pktptr->net_ip6dst);
	//kprintf("after print\n");
	byte ipdst[16];
	byte ipprefix[16];
	for(i=0; i< ND_ROUTETAB_SIZE;i++)
	{

		rtblptr = &ndroute_tab[i];

		preflen = rtblptr->ipaddr.preflen;
		preflen = preflen/8;
	

		memset(ipdst, 0, 16);
		memset(ipprefix, 0, 16);
		memcpy(ipprefix, rtblptr->nd_prefix, preflen);
		memcpy(ipdst, pktptr->net_ip6dst, preflen);

		if((memcmp((const void *)ipdst, (const void *)ipprefix, preflen) == 0) && rtblptr->state == RT_STATE_USED)
		{

			int32 retval = nd_ncfindip(rtblptr->ipaddr.ip6addr);
			memcpy(nxthop, rtblptr->ipaddr.ip6addr, 16);

			if(retval == SYSERR)
			{
				ncindex = nd_ncnew(nxthop, NULL, 
				pktptr->net_iface, NB_REACH_INC, 0);
				
				/* insert packet into the queue */
				nd_ncq_insert(pktptr, ncindex);
				
				/* Sending neighbor solicitation message */
				nd_ns_send(ncindex);
				
				//kprintf("Entry Found %d:%d\n", i, preflen);

			}
			else
			{

				//kprintf("Send the packet\n");
				nbcptr = &nbcache_tab[retval];
				ifptr = &if_tab[pktptr->net_iface];
				memcpy(pktptr->net_src, ifptr->if_macucast, ETH_ADDR_LEN);
				
				if(!isipmc(pktptr->net_ip6dst))
				{
					memcpy(pktptr->net_dst, nbcptr->nc_hwaddr, ETH_ADDR_LEN);
				
				}
				pktptr->net_type = htons(ETH_IPv6);
				ip6_hton(pktptr);
				iplen =  40 + ntohs(pktptr->net_ip6len);
				retval = write(ETHER0, (char *)pktptr, 14 + iplen);



			}




			break;

		}

	}
	return OK;

}


status ip6_send(struct netpacket *pktptr)
{


	intmask mask;
	mask = disable();
	int32 retval;
	uint32 iplen;
	bool8 nxthop_flag;
	uint16 chksm;
	struct ifentry  *ifptr; 
	struct nd_nbcentry *nbcptr;
	int32 ncindex;
	byte nxthop[16];
	switch(pktptr->net_ip6nh)
	{

		/* Handling ICMPv6 Packets */
		case IP_ICMP6:
			chksm = icmp6_chksum(pktptr);
			pktptr->net_icchksm = htons(chksm);
			break;


	}

	/* Next Hop determination */
	kprintf("Dest in IPsend:");
	ip6addr_print(pktptr->net_ip6dst);
	retval = ip6_route(pktptr, nxthop);
	
	/* Resolve an IPv6 Address to a Layer 2 address */
	
	kprintf("\nNext Hop in IPsend:");
	ip6addr_print(nxthop);
	if(memcmp(pktptr->net_ip6dst, nxthop , 16) == 0)
	{
		kprintf("nxthop is destip\n");
		retval = ip6addr_reso(pktptr);
		if(retval == SYSERR)
		{kprintf("destip NOT in NC\n");
			/* NB discovery should be done */
			/* Create an entry in the neighbor Cache and sets its state to INCOMPLETE */
			ncindex = nd_ncnew(pktptr->net_ip6dst, NULL, 
				pktptr->net_iface, NB_REACH_INC, 0);
			
			/* insert packet into the queue */
			nd_ncq_insert(pktptr, ncindex);
			
			
			/* Sending neighbor solicitation message */
			nd_ns_send(ncindex);
			
			restore(mask);
			return SYSERR;
		}
		else
		{		kprintf("destip in NC\n");
			nbcptr = &nbcache_tab[retval];

			ifptr = &if_tab[pktptr->net_iface];
			memcpy(pktptr->net_src, ifptr->if_macucast, ETH_ADDR_LEN);
			
			
			if(!isipmc(pktptr->net_ip6dst))
			{
				memcpy(pktptr->net_dst, nbcptr->nc_hwaddr, ETH_ADDR_LEN);
			}
			
			else if(pktptr->net_iface == 0)
			
			{
				pktptr->net_dst[0] = 0x33;
				pktptr->net_dst[1] = 0x33;
				memcpy(pktptr->net_dst + 2, pktptr->net_ip6dst + 12, 4);
			
			
			}
			
			else if(pktptr->net_iface == 1)
			{
				ifptr = &if_tab[1];
				
				pktptr->net_dst[0]=  ifptr->if_macbcast[0];
				pktptr->net_dst[1] = ifptr->if_macbcast[1];
				pktptr->net_dst[2] = ifptr->if_macbcast[2];
				pktptr->net_dst[3] = ifptr->if_macbcast[3];
				pktptr->net_dst[4] = ifptr->if_macbcast[4];
				pktptr->net_dst[5] = ifptr->if_macbcast[5]; 
			}
			else if(pktptr->net_iface == 2)
			{
				
				ifptr = &if_tab[2];
				pktptr->net_dst[0]=  ifptr->if_macbcast[0];
				pktptr->net_dst[1] = ifptr->if_macbcast[1];
				pktptr->net_dst[2] = ifptr->if_macbcast[2];
				pktptr->net_dst[3] = ifptr->if_macbcast[3];
				pktptr->net_dst[4] = ifptr->if_macbcast[4];
				pktptr->net_dst[5] = ifptr->if_macbcast[5]; 
			}
			pktptr->net_type = htons(ETH_IPv6);
			ip6_hton(pktptr);
			iplen =  40 + ntohs(pktptr->net_ip6len);
			retval = write(ETHER0, (char *)pktptr, 14 + iplen);
		}

	}
	
	freebuf((char *)pktptr);
	restore(mask);
	return retval;


}

/*-------------------------------------------------------
 * ip_ntoh: convert IP header fields to host order 
 -------------------------------------------------------*/
void ip6_ntoh(struct netpacket *pktptr)
{

	pktptr->net_ip6len = ntohs(pktptr->net_ip6len);
       
}

/*-------------------------------------------------------
 * ip_ntoh: convert IP header fields to host order 
 -------------------------------------------------------*/
void ip6_hton(struct netpacket *pktptr)
{

	pktptr->net_ip6len = htons(pktptr->net_ip6len);
       
}



/* -----------------------------------------------------------
 * ip6addr_print : Print IPv6 address for debugging purposes
 * ---------------------------------------------------------*/
void ip6addr_print(byte *ip6addr)
{
//	kprintf("\n");
	int32	i;
	uint16	*ptr16;

	ptr16 = (uint16 *)ip6addr;

	for(i = 0; i < 7; i++) {
		kprintf("%04X:", htons(*ptr16));
		ptr16++;					
	}
	kprintf("%04X \n", htons(*ptr16));
//	kprintf("\n");

}



/* -----------------------------------------------------------
 * ip6addr_print_ping : Print IPv6 address for ping6 and nc commands
 * ---------------------------------------------------------*/
void ip6addr_print_ping(byte *ip6addr)
{
	//kprintf("\n");
	int32	i;
	uint16	*ptr16;

	ptr16 = (uint16 *)ip6addr;

	for(i = 0; i < 7; i++) {
		kprintf("%04X:", htons(*ptr16));
		ptr16++;					
	}
	kprintf("%04X", htons(*ptr16));
	
}

/* -----------------------------------------------------------
 * hwaddr_print_ping : Print hw address for nc command
 * ---------------------------------------------------------*/
void hwaddr_print_ping(byte *hwaddr)
{
	//kprintf("\n");
	int32	i;
	uint8	*ptr8;

	ptr8 = (uint8 *)hwaddr;

	for(i = 0; i < ETH_ADDR_LEN; i++) {
		kprintf("%02X:", *ptr8);
		ptr8++;					
	}
	kprintf("%02X", *ptr8);
	
}
