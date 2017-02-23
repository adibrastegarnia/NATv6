#include <xinu.h>


void nat_init()
{

	intmask mask;
	mask = disable();

	kprintf("this function is called\n");
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
				kprintf("j:%d\n", j);
				memcpy(rtblptr->ipaddr.ip6addr, ifptr->if_ip6ucast[0].ip6addr,16);
				rtblptr->ipaddr.preflen = ifptr->if_ip6ucast[0].preflen;
				memcpy(rtblptr->nd_prefix, ifptr->if_ip6ucast[0].ip6addr, ifptr->if_ip6ucast[0].preflen);
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



	//ip6addr_print(pktptr->net_ip6dst);
	ifptr = &if_tab[pktptr->net_iface];

	/* Match IPv6 destination address with our unicast, multicast address, or ULA */
	if(!isipmc(pktptr->net_ip6dst))
	{
	
			for(i=0; i < ifptr->if_nipucast; i++)
			{
				/* Compare our IPv6 unicast address with packet destination address */
				if(!memcmp(pktptr->net_ip6dst, ifptr->if_ip6ucast[i].ip6addr, 16))
				{
				kprintf("found ip\n");
				ip6addr_print(pktptr->net_ip6dst);
				break;
				}
				if(i >= ifptr->if_nipucast)
				{
					restore(mask);
					return;
				}
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


	
	
	
	
	
	
	/*kprintf("nat in\n");
	int i =0;
	struct nd_routertbl *rtblptr;

	byte ipdst[16];
	byte ipprefix[16];

	byte nxthop[16];
	int32 preflen, ncindex;

	struct nd_nbcentry *nbcptr;

	uint32 iplen;
	struct ifentry *ifptr;

*/

	
	/*for(i=0; i < ND_ROUTETAB_SIZE; i++)
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
			

			pktptr->net_iface = rtblptr->iface;

			kprintf("ip packet is sent from nat in\n");

			int32 retval = nd_ncfindip(ipdst);
			memcpy(nxthop, ipdst, 16);

			*/
			/*if(retval == SYSERR)
			{
				ncindex = nd_ncnew(nxthop, NULL, 
				pktptr->net_iface, NB_REACH_INC, 0);
			*/	
				/* insert packet into the queue */
			//	nd_ncq_insert(pktptr, ncindex);
				
				/* Sending neighbor solicitation message */
			//	nd_ns_send(ncindex);
				
				//kprintf("Entry Found %d:%d\n", i, preflen);

		/*	}
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

					kprintf("%02x:", pktptr->net_dst[k]);


				}
				kprintf("\n");
				//pktptr->net_type = htons(ETH_IPv6);
				//ip6_hton(pktptr);
				iplen =  40 + (pktptr->net_ip6len);
				kprintf("ip len in nat in %d\n", iplen);
				retval = write(ETHER0, (char *)pktptr, 14 + iplen);



			}



		}



	}*/

	return;

}

