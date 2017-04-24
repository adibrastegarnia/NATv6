#include <xinu.h>

struct nat_translatetbl nattrans_tab[NAT_TBL_SIZE];


int32 nat_translatein(struct netpacket *);
int32 nat_translateout(struct netpacket *);


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
				memcpy(rtblptr->nd_prefix, ifptr->if_ip6ucast[1].ip6addr, ifptr->if_ip6ucast[1].preflen);
				rtblptr->state = RT_STATE_USED;
				rtblptr->iface = i;
				j++;
				break;
			}
			j++;

		}

	}
	
	/* Inititalize nat table entries to free*/
	for(i=0; i< NAT_TBL_SIZE; i++){
		nattrans_tab[i].state = NAT_STATE_FREE;
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
		restore(mask);
		return;

	}

	
	
	/* Check the interface is valid or not */
	if(pktptr->net_iface < 0 || pktptr->net_iface > NIFACES)
	{
		//kprintf("Invalid interface number %d\n", pktptr->net_iface);
		freebuf((char *)pktptr);
		restore(mask);
		return;

	}


	//kprintf("nat in with dest addr ");
	//ip6addr_print_ping(pktptr->net_ip6dst);
	//kprintf(" from interface %d\n", pktptr->net_iface);
	ifptr = &if_tab[pktptr->net_iface];

	/* Match IPv6 destination address with our unicast, multicast address, or ULA */
	if(!isipmc(pktptr->net_ip6dst))
	{
			for(i=0; i < ifptr->if_nipucast; i++)
			{
				/* Compare our IPv6 unicast address with packet destination address */
				if(!memcmp(pktptr->net_ip6dst, ifptr->if_ip6ucast[i].ip6addr, 16))
				{
					//kprintf("NAT ucast ip matches destip\n");
					
					//Check if this was from h0 to h1 or h2, since destip=natip
					if(pktptr->net_iface == 0){
						if(nat_translatein(pktptr) == OK){
							break; // Entry found - this packet is not for NAT box
							/* Continue to forward */
						}
					}
					//if not in translation table
					//This is actually for the Nat box- process it and return
					ip6_in_ext((struct netpacket *)pktptr);
					restore(mask);	
					return;
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
				//kprintf("NAT mcast ip matches destip\n");
				ip6_in_ext((struct netpacket *)pktptr);
				restore(mask);	
				return;

			}

		}
			/* For multicast, if destip is not NAT ip, we discard the packet.*/
			//kprintf("MCast Packet dropped\n");
			restore(mask);
			return;
	}


	/* The packet was not for the NAT box. So it must be forwarded. */
	
	//kprintf("Forwarding packet to ");
	//ip6addr_print_ping(pktptr->net_ip6dst);
	//kprintf("\n");
	struct nd_routertbl *rtblptr;

	byte ipdst[16];
	byte ipprefix[16];

	byte nxthop[16];
	int32 preflen,retval, ncindex;

	struct nd_nbcentry *nbcptr;

	uint32 iplen;

	//kprintf("ICMP identifier, seq = %d, %d\n", pktptr->net_icmpidentifier, pktptr->net_icmpseqno);
	

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
				/*we found dest iface */
				//kprintf("FWDING TO DEST IP!! \n");
				/* NAT box's i interface has the same prefix as the dest ip */
				pktptr->net_iface = i;

				/* check if this is to h0; it must be from h1/2 since h0-h0 will not get here*/
				if(i == 0){
					if(nat_translateout(pktptr) == OK){
					}
				}

				kprintf("After translate: type %d srcport %d destport %d srcip destip\n", pktptr->net_ip6nh, pktptr->net_udpsport, pktptr->net_udpdport);
				ip6addr_print(pktptr->net_ip6src);
				ip6addr_print(pktptr->net_ip6dst);
				
				retval = ip6_send(pktptr);

				restore(mask);
				return retval;
			}
			/* Otherwise Destination host is not local to the Nat box - has to be fwded to next eth0 router */
		}
	}
/*********************************************************/


	//kprintf("Checking routing table in NAT_in for"); 
	//ip6addr_print_ping(pktptr->net_ip6dst);
	//kprintf("\n");


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
			
			//kprintf("Fwd: Prefix matches i: %d, addr", i);
			//ip6addr_print_ping(ipdst);
			pktptr->net_iface = rtblptr->iface;
			//kprintf(" on interface %d ", pktptr->net_iface );
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

				restore(mask);
				return SYSERR;

			}
			else
			{
				//kprintf("Send the packet from nat in\n");
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
				restore(mask);
				return;


			}



		}



	}
	restore(mask);
	return;
}


//Translation from h1 or h2 to h0
int32  nat_translateout(struct netpacket *pktptr){
	/* When does packet have to be translated? - only when going from oth1/2 to eth0*/
	/* Dest ip will be remote ip - can be checked with prefix*/
	/* Src ip will be h1/2 - add into nat table, translate, and update checksum*/
	static uint16 nat_out_packetid = 0x80;
	int32 i;
	struct ifentry *ifptr;
	struct nat_translatetbl * nattblptr;


	/* Probably dont need this check - but added for safety*/
	// Check if dest ula is not local - then needs to be translated
	// loop through local ifaces and return if match - exclude eth0
	for(i = 1; i<NIFACES; i++){
		ifptr = &if_tab[i];	
		if(memcmp(pktptr->net_ip6dst, ifptr->if_ip6ucast[1].ip6addr, 2) == 0){
			/* prefix matches, dest ip is local, no need to translate*/
			return SYSERR;
		}
	}
	
	//kprintf("Nat Translateout - need to translate");

	ifptr = &if_tab[0]; /* interface 0 is the outgoing interface */
	/*Find free entry and add to table, then translate */
	for(i = 0; i < NAT_TBL_SIZE; i++){
		nattblptr = &nattrans_tab[i];	
		if(nattblptr->state == NAT_STATE_FREE)	{
			/* Add to table */
			memcpy(nattblptr->nat_iplocal,pktptr->net_ip6src, 16);
			memcpy(nattblptr->nat_ipremote,pktptr->net_ip6dst, 16);
			nattblptr->nat_packettype = pktptr->net_ip6nh;
			nattblptr->nat_iflocal = pktptr->net_iface;
			nattblptr->nat_packetidremote = nat_out_packetid++;
			nattblptr->state = NAT_STATE_USED;		
			//kprintf("NAT entry added at %d\n", i);

			/*Translate by replacing src ip, id/port, interface, checksum*/
			pktptr->net_iface = 0; /* TODO: is this always the case?*/
			memcpy(pktptr->net_ip6src, ifptr->if_ip6ucast[1].ip6addr, 16); /* ULA of Natbox on eth0*/

			
			/* update identifier and recalculate checksum*/
			/* TODO: Should we recalculate full checksum?- can we modify the current one slightly*/

			switch(pktptr->net_ip6nh)
			{
				/* Handling ICMPv6 Packets */
				case IP_ICMP6:
					nattblptr->nat_packetidlocal = pktptr->net_icmpidentifier;
					pktptr->net_icmpidentifier = nattblptr->nat_packetidremote; /* replacement packet id*/
					pktptr->net_icchksm = 0x0000; 
					pktptr->net_icchksm = htons(icmp6_chksum(pktptr));
					break;
				case IP_UDP:
					kprintf("UDP DETECTED in nat_translateout\n");
					nattblptr->nat_packetidlocal = pktptr->net_udpsport;
					pktptr->net_udpsport = nattblptr->nat_packetidremote; 
					pktptr->net_udpcksm = 0x0000;
					pktptr->net_udpcksm = htons(udp_cksum(pktptr));
					break;
				default:
					//kprintf("Unknown type DETECTED in nat_translateout\n");
					break;
			}
			return OK;
		}
	}

	/*We did not get free entry*/
	//kprintf("Could not translate: table full");
	/*TODO: Handle this by replacing LRU entry*/

	return OK;
}


//Translation from h0 to h1 or h2
int32  nat_translatein(struct netpacket *pktptr){
	/* When does packet have to be translated? - only when going from eth0 to oth1/2*/
	/* dest ip will be same as nat ip*/
	/* Source ip will be the remote ip*/
	/* look up table to see if entry exists*/
	/* if entry exists, Translate, upadte checksum and then free the table entry */
	int32 i;
	kprintf("In nat transin\n");
	struct nat_translatetbl * nattblptr;
	for(i = 0; i < NAT_TBL_SIZE; i++){
		nattblptr = &nattrans_tab[i];	
		if(nattblptr->state == NAT_STATE_USED)	{
			if( memcmp(nattblptr->nat_ipremote,pktptr->net_ip6src,16) == 0){ /*entry matches dest ip addr*/
				kprintf("Nat in remip matches\n");
kprintf("pkt->net_iface : %d",pktptr->net_iface);
	kprintf("pkt->net_udpdport : %d",pktptr->net_udpdport);
	kprintf("nattblptr->nat_packetidremote: %d\n",nattblptr->nat_packetidremote);

				if(((pktptr->net_icmpidentifier == nattblptr->nat_packetidremote) && (pktptr->net_ip6nh == IP_ICMP6))	/*Check id for icmp*/
				||((pktptr->net_udpdport == nattblptr->nat_packetidremote) && (pktptr->net_ip6nh == IP_UDP)))    /*Check id for UDP*/	
				{
					/*Entry matches*/
					//kprintf("Nat translatein - fount entry at %d\n", i);
					
					/*Translate back dest ip, id/port, iface, checksum*/
					memcpy(pktptr->net_ip6dst, nattblptr->nat_iplocal, 16); /*replace dest ip with local*/
					pktptr->net_iface = nattblptr->nat_iflocal; /* replace interface */
					
					/* Update id and checksum */

					switch(pktptr->net_ip6nh)	{
						/* Handling ICMPv6 Packets */
						case IP_ICMP6:
							pktptr->net_icmpidentifier = nattblptr->nat_packetidlocal; /* replacement packet id*/
							pktptr->net_icchksm = 0x0000; 
							pktptr->net_icchksm = htons(icmp6_chksum(pktptr));
							break;
						case IP_UDP:
							kprintf("UDP DETECTED in nat_translatein\n");
							pktptr->net_udpdport = nattblptr->nat_packetidlocal;
							pktptr->net_udpcksm = 0x0000;
							pktptr->net_udpcksm = htons(udp_cksum(pktptr));
							break;
						default:
							//kprintf("Unknown type DETECTED in nat_translatein\n");
							break;
					}
					nattblptr->state = NAT_STATE_FREE; /* Free the entry after first receive packet*/
					/* TODO: change freeing to be time based*/
					return OK;
				}
			}
		}
	}
	
	

	/* No entry found in table */
	return SYSERR;	
}

