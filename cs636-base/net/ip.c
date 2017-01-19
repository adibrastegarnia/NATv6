#include <xinu.h>


struct	iqentry ipoqueue; 


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
	ip6addr_print(ifptr->if_ip6mcast[index].ip6addr);

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

	
	ifptr = &if_tab[pktptr->net_iface];

	/* Match IPv6 destination address with our unicast ot multicast address */
	if(!isipmc(pktptr->net_ip6dst))
	{
		for(i=0; i < ifptr->if_nipucast; i++)
		{
			/* Compare our IPv6 unicast address with packet destination address */
			if(!memcmp(pktptr->net_ip6dst, ifptr->if_ip6ucast[i].ip6addr, 16))
			{
				break;

			}

		}
		if(i >= ifptr->if_nipucast)
		{

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
               	kprintf("Next header value %d\n", nh_value);

		switch(nh_value)
		{
			case IP6_EXT_HBH:
				kprintf("Hop by Hop header\n");
				return;

			case IP6_EXT_ICMP:
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


status ip6addr_reso(struct netpacket *pktptr)
{

	byte *ipdst[16];
	int32 i;
	memcpy(ipdst, pktptr->net_ip6dst, 16);

	struct nd_nbcentry *nbcptr;
	//ip6addr_print(ipdst);
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


status ip6_send(struct netpacket *pktptr)
{


	intmask mask;
	mask = disable();
	int32 retval;
	uint32 iplen;
	struct ifentry  *ifptr; 
	struct nd_nbcentry *nbcptr;

	retval = ip6addr_reso(pktptr);
	nbcptr = &nbcache_tab[retval];

	if(retval == SYSERR)
	{
		/* NB discovery should be done */
		kprintf("Address Resolution is failed\n");
		restore(mask);
		return SYSERR;

	}
	
	ifptr = &if_tab[pktptr->net_iface];
	
	memcpy(pktptr->net_src, ifptr->if_macucast, ETH_ADDR_LEN);
	memcpy(pktptr->net_dst, nbcptr->nc_hwaddr, ETH_ADDR_LEN);
        pktptr->net_type = htons(ETH_IPv6);


	int i;
	for(i= 0; i< 6;i++)
	{
		kprintf("%02x:", ifptr->if_macucast[i]);
	}
	kprintf("\n");
	
	ip6_hton(pktptr);
	iplen =  ntohs(pktptr->net_ip6len);
	kprintf("ip len %d:\n", 14 + iplen);
	retval = write(ETHER0, (char *)pktptr, 14 + iplen);
	
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
	kprintf("\n");
	int32	i;
	uint16	*ptr16;

	ptr16 = (uint16 *)ip6addr;

	for(i = 0; i < 7; i++) {
		kprintf("%04X:", htons(*ptr16));
		ptr16++;					
	}
	kprintf("%04X", htons(*ptr16));
	kprintf("\n");

}
