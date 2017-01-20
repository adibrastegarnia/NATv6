#include <xinu.h>

struct nd_nbcentry nbcache_tab[ND_NCACHE_SIZE];
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

	}

	/* initialize Routing table  */
	rtblptr = &ndroute_tab[0];
	memcpy(rtblptr->nd_prefix,ip6_llpref, 16);
	rtblptr->state = RT_STATE_USED;
	rtblptr->nd_onlink = TRUE;
	rtblptr->nd_defgtw = FALSE;
	rtblptr->nd_invatime = ND_INFINITE_TIME;


	for(i=1; i < ND_ROUTETAB_SIZE; i++)
	{
		rtblptr = &ndroute_tab[i];
		memset(rtblptr, 0, sizeof(struct nd_routertbl));
		rtblptr->state = RT_STATE_FREE;


	}
	restore(mask);
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


	/* Pointer to Neighbor Solicitation Message */
	nbsolptr = (struct nd_nbrsol *)pktptr->net_icdata;


	/* Validity Check */

	/* ICMP Code should be 0 */
	if(pktptr->net_iccode !=0)
	{
		return;
	}
	/* ICMP length is 24 or more octests */
	if(pktptr->net_ip6len < 24)
	{
		return;
	}

	/* Target address is not a multicast address */
	if(isipmc(nbsolptr->nd_trgtaddr))
	{
		return;
	}

	if(pktptr->net_ip6hl != 255)
	{
		return;
	}
	if(isipunspec(pktptr->net_ip6src))
	{
		if(memcmp(pktptr->net_ip6dst, ip6_nd_snmpref, 13))
		{
			return;

		}

	}
	mask = disable();
	struct ifentry *ifptr;
	ifptr = &if_tab[pktptr->net_iface];
	ip6addr_print(nbsolptr->nd_trgtaddr);
	for(i=0; i < ifptr->if_nipucast; i++)
	{
		if(!memcmp(ifptr->if_ip6ucast, nbsolptr->nd_trgtaddr, 16))
		{
			break;
		}
	}


	if(i >= ifptr->if_nipucast)
	{
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

	ip6addr_print(nbadvrptr->nd_trgtaddr);
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


	icmp6_send(ipdst, ICMP6_NAM_TYPE, 
			0 , nbadvrptr,
			nbadvrlen, 
			pktptr->net_iface);

	freemem((char *)nbadvrptr, nbadvrlen);
	restore(mask);

	return;

}


status nd_ns_send(int32 ncindex)
{


}

/*---------------------------------------------------------------
 * nd_in_nam: Handling Neighbour Advertisement incoming messages 
 * -------------------------------------------------------------*/

void nd_in_nam(struct netpacket *pktptr)
{
	struct nd_nbadvr *nbadvptr;

	
	


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
			nd_in_nsm(pktptr);
			break;
		/* Handling Neighbour Advertisment Packet */
		case ICMP6_NAM_TYPE:
			nd_in_nam(pktptr);
			break;
	

		case ICMP6_RAM_TYPE:
			kprintf("Router Advertisemet\n");
			break;
		case ICMP6_RDM_TYPE:
			break;
		case ICMP6_ECHREQ_TYPE:
			break;
		case ICMP6_ECHRES_TYPE:
			break;
	}

}


