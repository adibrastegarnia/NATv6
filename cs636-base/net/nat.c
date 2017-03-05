#include <xinu.h>


void nat_init()
{

	intmask mask;
	mask = disable();

	//kprintf("this function is called\n");
	struct ifentry *ifptr;
	struct nd_routertbl *rtblptr; 


	int i,j;
	j = 1;

        for (i=0; i<NIFACES; i++) {
		ifptr = &if_tab[i];
		while(j < ND_ROUTETAB_SIZE)
		{

			rtblptr = &ndroute_tab[j];
			if(rtblptr->state == RT_STATE_FREE)
			{
				//kprintf("j:%d\n", j);
				memcpy(rtblptr->ipaddr.ip6addr, ifptr->if_ip6ucast[1].ip6addr,16);
				rtblptr->ipaddr.preflen = ifptr->if_ip6ucast[1].preflen;
				memcpy(rtblptr->nd_prefix, ifptr->if_ip6ucast[1].ip6addr, ifptr->if_ip6ucast[0].preflen);
				rtblptr->state = RT_STATE_USED;
				rtblptr->iface = i;
				j++;
				break;
			}
			j++;

		}

	}

	restore(mask);
	return;



}



void nat_in(struct netpacket *pktptr)
{

	intmask mask;
	int i;
	struct	ifentry *ifptr; 	/* Network interface pointer	*/

        mask = disable();
	//ip6_ntoh(pktptr);

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


	kprintf("nat in with dest addr ");
	ip6addr_print_ping(pktptr->net_ip6dst);
	kprintf(" from interface %d\n", pktptr->net_iface);
	ifptr = &if_tab[pktptr->net_iface];

	/* Match IPv6 destination address with our unicast, multicast address, or ULA */
	if(!isipmc(pktptr->net_ip6dst))
	{
			for(i=0; i < ifptr->if_nipucast; i++)
			{
				/* Compare our IPv6 unicast address with packet destination address */
				if(!memcmp(pktptr->net_ip6dst, ifptr->if_ip6ucast[i].ip6addr, 16))
				{
					kprintf("NAT ucast ip matches destip\n");
					ip6_in_ext((struct netpacket *)pktptr);
					break;
				}
			}
			/* The unicast dest ip was not the NAT ip, so continue to forward.*/
	
	}
	else
	{
		for(i=0; i < ifptr->if_nipmcast; i++)
		{
			/* Compare our IPv6 Multicast address with packet destionation address */
			if(!memcmp(pktptr->net_ip6dst, ifptr->if_ip6mcast[i].ip6addr, 16))
			{
				kprintf("NAT mcast ip matches destip\n");
				ip6_in_ext((struct netpacket *)pktptr);
				restore(mask);	
				return;

			}

		}
			/* For multicast, if destip is not NAT ip, we discard the packet.*/
			kprintf("MCast Packet dropped\n");
			restore(mask);
			return;
	}


	/* The packet was not for the NAT box. So it must be forwarded. */
	
	kprintf("Forwarding packet\n");

	struct nd_routertbl *rtblptr;

	byte ipdst[16];
	byte ipprefix[16];

	byte nxthop[16];
	int32 preflen,retval, ncindex;

	struct nd_nbcentry *nbcptr;

	uint32 iplen;



/*******************************************************/
	/* Check the destination address is Unique local address */
	if(isipula(pktptr->net_ip6dst))
	{        
		for (i=0; i<NIFACES; i++) 
		{
			ifptr = &if_tab[i];
			//Compare the prefix
			if(!memcmp(pktptr->net_ip6dst, ifptr->if_ip6ucast[1].ip6addr, 2))
			{
				kprintf("FWDING TO DEST IP!! \n");
				/* NAT box's i interface has the same prefix as the dest ip */
				pktptr->net_iface = i;

/*Update checksum*/
		switch(pktptr->net_ip6nh)
	{
		case IP_ICMP6:
			pktptr->net_icchksm = htons(icmp6_chksum(pktptr));
			break;
	}

				retval = ip6_send(pktptr);
				restore(mask);
				return retval;
			}
			/* Otherwise Destination host is not local to the Nat box - has to be fwded to next eth0 router */
		}
	}
/*********************************************************/



	
	for(i=0; i < ND_ROUTETAB_SIZE; i++)
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
			
			kprintf("Fwd: Prefix matches i: %d, addr", i);
			ip6addr_print_ping(ipdst);
			pktptr->net_iface = rtblptr->iface;
			kprintf(" on interface %d ", pktptr->net_iface );
			//kprintf("ip packet is sent from nat in\n");

			int32 retval = nd_ncfindip(ipdst);
			memcpy(nxthop, ipdst, 16);

		
			if(retval == SYSERR)
			{
				ncindex = nd_ncnew(nxthop, NULL, 
				pktptr->net_iface, NB_REACH_INC, 0);
				
				/* insert packet into the queue */
				nd_ncq_insert(pktptr, ncindex);
				
				/* Sending neighbor solicitation message */
				nd_ns_send(ncindex);
				
				/* The ND code will take care of sending this packet */

			}
			else
			{
				kprintf("Send the packet from nat in\n");
				nbcptr = &nbcache_tab[retval];
				ifptr = &if_tab[pktptr->net_iface];
				memcpy(pktptr->net_src, ifptr->if_macucast, ETH_ADDR_LEN);
				
				if(!isipmc(pktptr->net_ip6dst))
				{
					memcpy(pktptr->net_dst, nbcptr->nc_hwaddr, ETH_ADDR_LEN);
				
				}
				int k=0;
				for(k=0; k < 6; k++)
				{

					//kprintf("%02x:", pktptr->net_dst[k]);


				}
				//kprintf("\n");
				//pktptr->net_type = htons(ETH_IPv6);
				//ip6_hton(pktptr);
				iplen =  40 + (pktptr->net_ip6len);
				//kprintf("ip len in nat in %d\n", iplen);
				retval = write(ETHER0, (char *)pktptr, 14 + iplen);



			}



		}



	}
	restore(mask);
	return;

}

