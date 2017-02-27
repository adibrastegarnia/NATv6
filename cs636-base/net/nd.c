#include <xinu.h>
#include <stdlib.h>
/* Neighbor Cache */
struct nd_nbcentry nbcache_tab[ND_NCACHE_SIZE];
/* Routing Table */
struct nd_routertbl ndroute_tab[ND_ROUTETAB_SIZE];  
/* -----------------------------------------------
 * nd_init: Initialize neighbor discovery data structures 
 * ----------------------------------------------*/

void nd_init(void)
{

	struct nd_nbcentry *ncptr;
	struct nd_routertbl *rtblptr;
	intmask mask;

	int32 i;

	mask = disable();


	/* Initialize Neighbour Cache */
	for(i=0; i < ND_NCACHE_SIZE; i++)
	{

		ncptr = &nbcache_tab[i];
		memset(ncptr, 0, sizeof(struct nd_nbcentry));
		ncptr->nc_state = NC_STATE_FREE;
		ncptr->nc_pqhead = 0;
		ncptr->nc_pqtail = 0;
		ncptr->nc_pqcount = 0;
		ncptr->nc_reachstate = NB_REACH_FREE;
		ncptr->nc_retries = 0;

	}

	/* initialize Routing table  */
	rtblptr = &ndroute_tab[0];
	memcpy(rtblptr->nd_prefix,ip6_llpref, 16);
	rtblptr->state = RT_STATE_USED;
	rtblptr->nd_onlink = TRUE;
	rtblptr->nd_defgtw = FALSE;
	rtblptr->nd_invatime = ND_INFINITE_TIME;
	rtblptr->ipaddr.preflen = 16; 

	for(i=1; i < ND_ROUTETAB_SIZE; i++)
	{
		rtblptr = &ndroute_tab[i];
		memset(rtblptr, 0, sizeof(struct nd_routertbl));
		rtblptr->state = RT_STATE_FREE;


	}
	
	restore(mask);
	/* Create a process for the ND timer */
	resume(create(nd_timer, 4196, 2000, "nd_timer", 0, NULL));

	return;
}

/* ----------------------------------------------------
 * nd_ncq_insert:insert a packet into the NC queue 
 * -------------------------------------------------*/
void nd_ncq_insert(struct netpacket *pktptr, int32 ncindex)
{
	struct nd_nbcentry *nbcptr;
	nbcptr = &nbcache_tab[ncindex];
	if(nbcptr->nc_pqcount < NC_PKTQ_SIZE)
	{
		nbcptr->nc_pktq[nbcptr->nc_pqtail++] = pktptr;
		if(nbcptr->nc_pqtail >= NC_PKTQ_SIZE)
		{
			nbcptr->nc_pqtail = 0;


		}
		nbcptr->nc_pqcount++;
		
	}
	else if(nbcptr->nc_pqcount == NC_PKTQ_SIZE)
	{
		freebuf((char *)nbcptr->nc_pktq[nbcptr->nc_pqtail]);
        	nbcptr->nc_pktq[nbcptr->nc_pqtail] = pktptr;


	}

	return;

}



/* --------------------------------------------------
 * nd_ncfindip: Find an entry in the Neighbor cache
 * ------------------------------------------------*/
int32 nd_ncfindip(byte *ip6addr)
{

	int i=0;
	struct nd_nbcentry *nbcptr;
	for(i=0 ;i < ND_NCACHE_SIZE; i++)
	{
		nbcptr = &nbcache_tab[i];

		if(nbcptr->nc_state == NC_STATE_FREE)
			continue;


		if(!memcmp(nbcptr->nc_nbipucast, ip6addr, 16))
		{
			return i;

		}

	}

	return SYSERR;

}

/* --------------------------------------------------
 * nd_ncupdate: Update a Neighbor Cache Entry 
 * -------------------------------------------------*/

int32 nd_ncupdate(byte *ip6addr,
		  byte *hwaddr,
		  int32 isrouter,
		  bool8 irvalid)
{
	struct nd_nbcentry  *nbcptr;


	intmask mask;

	int32 ncindex;
	mask = disable();


	ncindex = nd_ncfindip(ip6addr);

	if(ncindex == SYSERR)
	{
		restore(mask);
		return SYSERR;

	}

	nbcptr = &nbcache_tab[ncindex];
	if(memcmp(nbcptr->nc_hwaddr, hwaddr, ETH_ADDR_LEN))
	{

		memcpy(nbcptr->nc_hwaddr, hwaddr, ETH_ADDR_LEN);
		nbcptr->nc_reachstate = NB_REACH_STA; 

	
	}


	if(irvalid)
	{
		nbcptr->nc_isrouter = isrouter;

	}


	restore(mask);
	return OK;

}

/*------------------------------------------------------------------
 * nd_ncnew: Add a new entry into the neighbor cache 
 * ---------------------------------------------------------------*/

int32 nd_ncnew(byte *ip6addr,
	       byte *hwaddr,
	       int32 iface,
	       int32 rstate,
	       int32 isrouter)
{
	struct nd_nbcentry  *nbcptr;
	int32 i;

	for(i=0; i < ND_NCACHE_SIZE;i++)
	{
		nbcptr = &nbcache_tab[i];

		if(nbcptr->nc_state == NC_STATE_FREE)
		{
			break;

		}

	}
	if(i >= ND_NCACHE_SIZE)
	{
		kprintf("Neighbor Cache is full\n");
		return SYSERR;

	}

	memset(nbcptr, 0 ,sizeof(struct nd_nbcentry));

	nbcptr->nc_iface = iface;
	nbcptr->nc_reachstate = rstate;
	memcpy(nbcptr->nc_nbipucast, ip6addr, 16);

	if(hwaddr)
	{
		memcpy(nbcptr->nc_hwaddr, (void *)hwaddr, ETH_ADDR_LEN);


	}
	nbcptr->nc_isrouter = isrouter;
	if(nbcptr->nc_reachstate == NB_REACH_INC)
	{
		nbcptr->nc_texpire = ND_RETRAN_TIME;

	}
	else
	{
		nbcptr->nc_texpire = ND_REACH_TIME;

	}

	nbcptr->nc_state = NC_STATE_USED;
	return i;

}



/*-------------------------------------------------------------
 * nd_in_nsm: Handling Neighbor soliciation incoming messages 
 * ------------------------------------------------------------*/

void nd_in_nsm(struct netpacket *pktptr)
{
	
	
	intmask mask;
	struct nd_nbrsol *nbsolptr;
	struct nd_nbadvr *nbadvrptr;
	struct nd_opt    *nboptptr;
	byte *ipdst;
	int32 i=0;


	//kprintf("ns message\n");
	/* Pointer to Neighbor Solicitation Message */
	nbsolptr = (struct nd_nbrsol *)pktptr->net_icdata;

	
	/* Validity Check */

	/* ICMP Code should be 0 */
	if(pktptr->net_iccode !=0)
	{
		kprintf("ICMP Code is wrong\n");
		return;
	}
	/* ICMP length is 24 or more octests */
	if(pktptr->net_ip6len < 24)
	{
		kprintf("ICMP length is greatar than 24\n");
		return;
	}

	/* Target address is not a multicast address */
        //ip6addr_print(nbsolptr->nd_trgtaddr);

	if(isipmc(nbsolptr->nd_trgtaddr))
	{
		kprintf("Target address is a multicast address\n");
		//		return;
	}

	if(pktptr->net_ip6hl != 255)
	{
		kprintf("Hop limit is worng\n");
		return;
	}
	if(isipunspec(pktptr->net_ip6src))
	{
		if(memcmp(pktptr->net_ip6dst, ip6_nd_snmpref, 13))
		{
			kprintf("IP doesn't match\n");
			return;

		}

	}
	mask = disable();
	struct ifentry *ifptr;
	ifptr = &if_tab[pktptr->net_iface];
	//kprintf("Target Address: ");
	//ip6addr_print(nbsolptr->nd_trgtaddr);
	//kprintf("IP source: ");
	//ip6addr_print(ifptr->if_ip6ucast[0].ip6addr);
	for(i=0; i < ifptr->if_nipucast; i++)
	{
		if(!memcmp(ifptr->if_ip6ucast[i].ip6addr, nbsolptr->nd_trgtaddr, 16))
		{
			//kprintf("IP match");
			break;
		}

	}


	if(i >= ifptr->if_nipucast)
	{
		kprintf("Error\n");
		restore(mask);
		return;

	}

	/* Extract Option from NB solicitation message */
	nboptptr = (struct nd_opt *)nbsolptr->nd_opts;
	//kprintf("In ND_IN_NS:%d\n", nboptptr->nd_type);

	switch(nboptptr->nd_type)
	{
		case ND_OPT_SLLA:

			/* If the Source Address is the unspecified address, 
			 * the node MUST NOT create or update 
			 * the Neighbor Cache entry */
			//ip6addr_print(pktptr->net_ip6src);
			if(isipunspec(pktptr->net_ip6src))
			{
				restore(mask);
				return;

			}

			if(nd_ncfindip(pktptr->net_ip6src) != SYSERR)
			{
				/* Update the entry which is found in the NB cache */
				nd_ncupdate(pktptr->net_ip6src, 
						nboptptr->nd_lladr, 
						FALSE, 0);
			}
			/* Create a New entry in NB cache data strucutre */
			else
			{
			nd_ncnew(pktptr->net_ip6src, 
					nboptptr->nd_lladr,
					pktptr->net_iface, 
					NB_REACH_STA, FALSE);
			}

			break;

	}
	/* Sending Solicited Neighbor Advertisements */
        int32 nbadvrlen = sizeof(struct nd_nbadvr) + 8;


	nbadvrptr = (struct nd_nbadvr *)getmem(nbadvrlen);
	if((int32)nbadvrptr == SYSERR)
	{

		restore(mask);
		return;

	}
	memcpy(nbadvrptr->nd_trgtaddr, nbsolptr->nd_trgtaddr, 16);

	//ip6addr_print(nbadvrptr->nd_trgtaddr);
	nbadvrptr->nd_r = 0;
	nbadvrptr->nd_s = 1;
	nbadvrptr->nd_o = 1;
	memcpy(nbadvrptr->nd_reserved, 0x000, 3);

	nboptptr = (struct nd_opt *)nbadvrptr->nd_opts;
	nboptptr->nd_type = ND_OPT_TLLA;
	nboptptr->nd_len = 1;
	memcpy(nboptptr->nd_lladr, if_tab[pktptr->net_iface].if_macucast, ETH_ADDR_LEN);


	if(isipunspec(pktptr->net_ip6src))
	{

		nbadvrptr->nd_s = 0;
		ipdst = ip6_allnodesmc; 
	}
	else
	{
		ipdst = pktptr->net_ip6src;
	}


	//kprintf("\nNeighbor adver sent ip dst: \n");
	//ip6addr_print(ipdst);
	icmp6_send(ipdst, ICMP6_NAM_TYPE, 
			0 , nbadvrptr,
			nbadvrlen, 
			pktptr->net_iface);

	freemem((char *)nbadvrptr, nbadvrlen);
	restore(mask);

	return;

}

/* ----------------------------------------------------
 * nd_ns_send: Send a neighbor solicitation message 
 * ---------------------------------------------------*/

status nd_ns_send(int32 ncindex)
{

	struct nd_nbrsol *nbsptr;
	struct nd_nbcentry *nbcptr;
	struct nd_opt *ndoptptr;

	byte ipdst[16];

	int32 nslen = sizeof(struct nd_nbrsol) + 8;
	nbcptr = &nbcache_tab[ncindex];

	nbsptr = (struct nd_nbrsol *)getmem(nslen);
	memset(nbsptr, 0, nslen);

	ndoptptr = (struct nd_opt *)nbsptr->nd_opts;

	
	memcpy(nbsptr->nd_trgtaddr, nbcptr->nc_nbipucast, 16);
	ndoptptr->nd_type = ND_OPT_SLLA ;
	ndoptptr->nd_len = 1;

	memcpy(ndoptptr->nd_lladr, if_tab[nbcptr->nc_iface].if_macucast, ETH_ADDR_LEN);

	if(nbcptr->nc_reachstate == NB_REACH_INC)
	{
		
		memcpy(ipdst, ip6_nd_snmpref, 16);
		memcpy(ipdst + 13, nbcptr->nc_nbipucast + 13 , 3);
		//memcpy(ipdst + 13, if_tab[nbcptr->nc_iface].if_ip6ucast[0].ip6addr + 13, 3);
		//ip6addr_print(ipdst);
		ip6addr_print(ipdst);
	}
	else
	{
		memcpy(ipdst, nbcptr->nc_nbipucast, 16);

	}

        icmp6_send(ipdst, ICMP6_NSM_TYPE, 
			0 , nbsptr,
			nslen, 
			nbcptr->nc_iface);

       freemem((char *)nbsptr, nslen);

       return OK;



}

/*---------------------------------------------------------------
 * nd_in_nam: Handling Neighbour Advertisement incoming messages 
 * -------------------------------------------------------------*/

void nd_in_nam(struct netpacket *pktptr)
{
	struct nd_nbadvr *nbadvptr;
	struct nd_nbcentry *nbcptr;
        struct nd_opt    *nboptptr;

	struct netpacket *pktptrip6;
	status retval;
	nbadvptr = (struct nd_nbadvr *)pktptr->net_icdata;
        nboptptr = (struct nd_opt *)nbadvptr->nd_opts;


	
	/* the Neighbor Cache is searched for the target's entry */
	retval = nd_ncfindip(nbadvptr->nd_trgtaddr);

	kprintf("IN NAM\n");
	//ip6addr_print(nbadvptr->nd_trgtaddr);
	if(retval == SYSERR)
	{

	

		return;
	}

	nbcptr = &nbcache_tab[retval];
	int32 rstate = nbcptr->nc_reachstate;

	//kprintf("rstate nd_in_nam:%d\n", rstate);
	switch(rstate)
	{

		case NB_REACH_INC:
			kprintf("INCOMPLETE STATE\n");
			switch(nboptptr->nd_type)
			{
				case ND_OPT_TLLA:
					/* the advertisement's Solicited flag is set, the state of the
					 * entry is set to REACHABLE
					 *  sets the IsRouter flag in the cache entry based on the Router
					 *  flag*/
					if(nbadvptr->nd_s == 1 && nbadvptr->nd_r == 0)
					{
						memcpy(nbcptr->nc_hwaddr, nboptptr->nd_lladr, ETH_ADDR_LEN);
						nbcptr->nc_reachstate = NB_REACH_REA; 
						nbcptr->nc_isrouter = FALSE;

					}
					else if(nbadvptr->nd_s == 1 && nbadvptr->nd_r == 1)
					{
						memcpy(nbcptr->nc_hwaddr, nboptptr->nd_lladr, ETH_ADDR_LEN);
						nbcptr->nc_reachstate = NB_REACH_REA; 
						nbcptr->nc_isrouter = TRUE;


					}
					else if(nbadvptr->nd_s == 0 && nbadvptr->nd_r == 0)
					{

						nd_ncupdate(pktptr->net_ip6src, 
						nboptptr->nd_lladr, 
						FALSE, 0);
					
					}
					else if(nbadvptr->nd_s == 0 && nbadvptr->nd_r == 1)
					{

						nd_ncupdate(pktptr->net_ip6src, 
						nboptptr->nd_lladr, 
						TRUE, 1);

					}
					/* sends any packets queued for the neighbor awaiting address resolution */
					while(nbcptr->nc_pqhead <= nbcptr->nc_pqtail || nbcptr->nc_pqcount==0)	{
						nbcptr->nc_pqcount--;
						pktptrip6 = nbcptr->nc_pktq[nbcptr->nc_pqhead++];
						pktptrip6->net_icchksm = 0x0000;
						ip6_send(pktptrip6);

					}
					break;
				default:kprintf("DEFAULT STATE\n");
					return;
			}

	}
	


}
/* ---------------------------------------------------
 * nd_rs_send: Send a Router Soliciation Message 
 * -------------------------------------------------*/

status nd_rs_send(int32 iface)
{
	intmask mask;
	mask = disable();

	struct nd_rsm *ndrsmptr;
	struct nd_opt *ndoptptr;
	int32 rsmlen = sizeof(struct nd_rsm) + 8;

	byte ipdst[16];

	ndrsmptr = (struct nd_rsm *)getmem(rsmlen);
	memset(ndrsmptr, 0, rsmlen);
	ndoptptr = (struct nd_opt *)ndrsmptr->nd_opts;

	ndoptptr->nd_type = ND_OPT_SLLA ;
	ndoptptr->nd_len = 1;
	memcpy(ndoptptr->nd_lladr, if_tab[iface].if_macucast, ETH_ADDR_LEN);

	/*  The host SHOULD delay the
	 *  transmission for a random amount of time between 0 and
	 *  MAX_RTR_SOLICITATION_DELAY */
	int32 rand_delay = rand() % MAX_RTR_SOLICITATION_DELAY  + 1;
	//kprintf("Random Delay: %d\n", rand_delay);
	sleepms(rand_delay);
	/* Destination address is All routers multicast address */
	memcpy(ipdst, ip6_allroutermc, 16);
	icmp6_send(ipdst, ICMP6_RSM_TYPE, 0 , ndrsmptr,rsmlen, iface);
        freemem((char *)ndrsmptr, rsmlen);

	kprintf("ND RS Message Sent\n");
	restore(mask);
	return OK;

}

/* nd_rsm_in: Handling an incoming Router Soliciation Message */
void nd_rsm_in(struct netpacket *pktptr)
{

	struct nd_rsm *ndrsmptr;
	struct nd_opt *ndoptptr;
	struct nd_roadv *roadvptr;

	struct ifentry *ifptr;
	intmask mask;
	mask  = disable();
	byte ipdst[16];


	/* ICMP Code should be 0 */
	if(pktptr->net_iccode !=0)
	{
		kprintf("ICMP Code is wrong\n");
		return;
	}

	/* ICMP Hop Limit should be 255 */
	if(pktptr->net_ip6hl != 255)
	{

		kprintf("ICMP Hop Limit Should be 255\n");
		return;

	}
	/* ICMP length is 8 or more octests */
	if(pktptr->net_ip6len < 8)
	{
		kprintf("ICMP length is greatar than 8\n");
		return;
	}




	ndrsmptr = (struct nd_rsm *)pktptr->net_icdata;
	ndoptptr = (struct nd_opt *)ndrsmptr->nd_opts;


	switch(ndoptptr->nd_type)
	{
		case ND_OPT_SLLA:

			if(isipunspec(pktptr->net_ip6src))
			{
				restore(mask);
				return;

			}

			if(nd_ncfindip(pktptr->net_ip6src) != SYSERR)
			{
				/* Update the entry which is found in the NB cache */
				nd_ncupdate(pktptr->net_ip6src, 
						ndoptptr->nd_lladr, 
						FALSE, 0);
			}
			/* Create a New entry in NB cache data strucutre */
			else
			{
			nd_ncnew(pktptr->net_ip6src, 
					ndoptptr->nd_lladr,
					pktptr->net_iface, 
					NB_REACH_STA, FALSE);
			}

			break;

	}




	int32 roadvrlen = sizeof(struct nd_roadv) + 32;
	roadvptr = (struct nd_roadv *)getmem(roadvrlen);
	ndoptptr = (struct nd_opt *)roadvptr->nd_opts;

	if((int32)roadvptr == SYSERR)
	{

		restore(mask);
		return;

	}
	memset(roadvptr, 0 , roadvrlen);
	

	roadvptr->nd_curhl = 255;
	roadvptr->nd_m = 0;
	roadvptr->nd_o = 0;
	roadvptr->nd_rolftime = 65535;
	roadvptr->nd_reachtime = 0;
	roadvptr->nd_retranstime = 0;
	
	ndoptptr->nd_type = ND_OPT_PREIF;
	ndoptptr->nd_len = 4;
	ndoptptr->nd_preflen = 16;
	memset(ndoptptr->nd_res1, 0, sizeof(byte));
	ndoptptr->nd_vallftime = 0xffffffff;
	ndoptptr->nd_preflftime = 0xffffffff;
	memset(ndoptptr->nd_res2, 0 , sizeof(uint32));
        
	ifptr = &if_tab[pktptr->net_iface];
	memcpy(ndoptptr->nd_prefix, ip6_ulapref, 16);


	if(pktptr->net_iface == 1)
	{

		ifptr = &if_tab[2];
		memcpy(ndoptptr->nd_prefix, ifptr->if_ip6ucast[1].ip6addr, 2);

	}
	else
	{
		ifptr = &if_tab[1];
		memcpy(ndoptptr->nd_prefix, ifptr->if_ip6ucast[1].ip6addr, 2);

	}
	//ip6addr_print(ndoptptr->nd_prefix);


	if(isipunspec(pktptr->net_ip6src))
	{

		memcpy(ipdst, ip6_allnodesmc, 16); 
	}
	else
	{
		memcpy(ipdst, pktptr->net_ip6src, 16);
	}

	/* Sending Router Advertisment Message */

	icmp6_send(ipdst, ICMP6_RAM_TYPE, 
			0 , roadvptr,
			roadvrlen, 
			pktptr->net_iface);

	freemem((char *)roadvptr, roadvrlen);
	restore(mask);
	return;

}

/* --------------------------------------------------
 * nd_ram_in: Handling Router Advertisement Message 
 * -------------------------------------------------*/

void nd_ram_in(struct netpacket *pktptr)
{
	struct nd_roadv *roadvptr;
	struct nd_opt  *ndoptptr;
	roadvptr = (struct nd_roadv *)pktptr->net_icdata;
	ndoptptr = (struct nd_opt *)roadvptr->nd_opts;

	intmask mask;
	mask = disable();

	/* IP Source Address is a link-local address */

	if(!isipllu(pktptr->net_ip6src))
	{

		restore(mask);
		return;

	}



	/* ICMP Code should be 0 */
	if(pktptr->net_iccode !=0)
	{
		kprintf("ICMP Code is wrong\n");
		return;
	}

	/* ICMP Hop Limit should be 255 */
	if(pktptr->net_ip6hl != 255)
	{

		kprintf("ICMP Hop Limit Should be 255\n");
		return;

	}
	/* ICMP length is 8 or more octests */
	if(pktptr->net_ip6len < 16)
	{
		kprintf("ICMP length is greatar than 8\n");
		return;
	}


	/* Update the Prefix List */
	int32 i;
	struct nd_routertbl *rtblptr;
	for(i=0; i< ND_ROUTETAB_SIZE; i++)
	{
		rtblptr = &ndroute_tab[i];
		if(rtblptr->state == RT_STATE_FREE)
		{
			rtblptr->state = RT_STATE_USED;
			memcpy(rtblptr->ipaddr.ip6addr, pktptr->net_ip6src,16);
			rtblptr->ipaddr.preflen = ndoptptr->nd_preflen;
			memcpy(rtblptr->nd_prefix,ndoptptr->nd_prefix, 16);
			break;
			

		}
		 
		
	}


	//ip6addr_print(pktptr->net_ip6src);
	//kprintf("nd pref len %d\n", (ndoptptr->nd_preflen));
	//ip6addr_print(ndoptptr->nd_prefix);
 	
	
	restore(mask);

	return;

}



/* ------------------------------------------------------
 * nd_in: Handling Neighboud discovery incoming packets 
 * -----------------------------------------------------*/
void nd_in(struct netpacket *pktptr)
{

	switch(pktptr->net_ictype)
	{
		/* Handling Neighbour Soliciation Packet */
		case ICMP6_NSM_TYPE:
			kprintf("Neighbor Solicitation Message\n");
			nd_in_nsm(pktptr);
			break;
		/* Handling Neighbour Advertisment Packet */
		case ICMP6_NAM_TYPE:
			kprintf("Neighbor Advertisement Message\n");
			nd_in_nam(pktptr);
			break;
	

		case ICMP6_RAM_TYPE:
			kprintf("Router Advertisemet\n");
			nd_ram_in(pktptr);
			break;
		case ICMP6_RDM_TYPE:
			break;
		case ICMP6_RSM_TYPE:
			kprintf("Router Solicitation Message\n");
			nd_rsm_in(pktptr);
			break;
		
	}

}

/*------------------------------------------------------
 * nd_timer: Neighbor discovery timer 
 * ----------------------------------------------------*/

process nd_timer()
{
	int32 ncindex;
	struct nd_nbcentry *nbcptr;

	intmask mask;
	while(TRUE)
	{
		mask = disable();

		for(ncindex=0; ncindex < ND_NCACHE_SIZE; ncindex++)
		{	
			nbcptr = &nbcache_tab[ncindex];
			if(nbcptr->nc_state == NC_STATE_FREE)
			{
				continue;

			}
			if(nbcptr->nc_reachstate == NB_REACH_INC)
			{
				//kprintf("time:%d\n", nbcptr->nc_texpire);
				if(nbcptr->nc_texpire-- <=0)
				{
					if(nbcptr->nc_retries < MAX_UNICAST_SOLICIT)
					{
						nd_ns_send(ncindex);
						nbcptr->nc_retries++;
						nbcptr->nc_texpire = ND_RETRAN_TIME; 
					}
					else
					{
						while(nbcptr->nc_pqcount > 0)
						{


							freebuf(nbcptr->nc_pktq[nbcptr->nc_pqtail++]);
							if(nbcptr->nc_pqtail  > NC_PKTQ_SIZE)
							{

								nbcptr->nc_pqtail = 0;
							}

							nbcptr->nc_pqcount--;


						}

						nbcptr->nc_state = NC_STATE_FREE;  

					}


				}
			}
		}
		restore(mask);
		sleepms(1);
	}



}


