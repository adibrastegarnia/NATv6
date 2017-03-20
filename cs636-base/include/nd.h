#define NC_PKTQ_SIZE	2   /* Neigbour cache (NC) queue size */
#define ND_NCACHE_SIZE  20  /* Neighbour cache size 	      */
#define ND_ROUTETAB_SIZE 20 /* Routing table size 	      */
#define ND_INFINITE_TIME -1 
#define NAT_TBL_SIZE 20

#define NC_STATE_FREE   0
#define NC_STATE_USED   1


#define RT_STATE_FREE 0
#define RT_STATE_USED 1

#define NAT_STATE_FREE	0
#define NAT_STATE_USED	1
/* neighbor's reachability state */
#define NB_REACH_FREE -1;
#define NB_REACH_INC  0
#define NB_REACH_REA  1
#define NB_REACH_STA  2
#define NB_REACH_DEL  3
#define NB_REACH_PROB 4


/* Option names and values */
#define ND_OPT_SLLA   1
#define ND_OPT_TLLA   2
#define ND_OPT_PREIF  3
#define ND_OPT_RH     4
#define ND_OPT_MTU    5


#define ND_REACH_TIME  30000
#define ND_RETRAN_TIME 1000
#define MAX_UNICAST_SOLICIT 3
#define MAX_RTR_SOLICITATION_DELAY 1000

/* Router Solicitation message format */
#pragma pack(1)
struct nd_rsm{

	uint32 nd_reserved;
	byte nd_opts[];
};

#pragma pack(0)




/* Router Advertisement Message Format */
#pragma pack(1)
struct nd_roadv
{
	byte nd_curhl;        	/* current Hop Limit 	*/
	byte nd_m:1;
	byte nd_o:1;
	byte nd_resv:6;
	uint16 nd_rolftime;   	/* Router Lifetime   	*/
	uint32 nd_reachtime;  	/*  Reachbale time    	*/
	uint32 nd_retranstime;  /* Retrans time 	*/
	byte   nd_opts[];
	

};
#pragma pack(0)



/* Neighbor Solicitation Message structure */
#pragma pack(1)
struct nd_nbrsol{
	
	uint32 nd_reserved;
	byte  nd_trgtaddr[16];
	byte  nd_opts[];

};
#pragma pack(0)



/* Neighbor Advertisement Message */
#pragma pack(1)
struct nd_nbadvr{

	byte   nd_r:1;
	byte   nd_s:1;
	byte   nd_o:1;
	byte nd_reserved[3];
	byte   nd_trgtaddr[16];
	byte   nd_opts[];
};
#pragma pack(0)

/* ND Option structure */
#pragma pack(1)
struct nd_opt{
	byte nd_type;
	byte nd_len;

	union
	{
		struct {
			byte  nd_lladr[16];         /* Source or target link layer address */
		};

		/* Prefix Information */
		struct {
			byte nd_preflen;
			byte nd_res1:6;
			byte nd_a:1;
			byte nd_l:1;			
			uint32 nd_vallftime;
			uint32 nd_preflftime;
			uint32 nd_res2;
			byte   nd_prefix[NIFACES-1][16];

		};

	};


};
#pragma pack(0)


/*  Neighbor Cache data strucutre */
struct nd_nbcentry
{
	int32 nc_state;
	byte  nc_nbipucast[16];
	byte  nc_hwaddr[ETH_ADDR_LEN];
	int32 nc_isrouter;
	int32 nc_texpire;
	int32 nc_retries;
	int32 nc_reachstate;
	int32 nc_iface;
	int32 nc_numprobes;
	int32 nc_tschevent;
	void  	*nc_pktq[NC_PKTQ_SIZE];
	int32   nc_pqhead;
	int32   nc_pqtail;
	int32   nc_pqcount;

};

/* Integrated Prefix List and Default Router list  */
struct nd_routertbl{
	byte nd_prefix[16];
	int32 nd_invatime;
	bool8 nd_defgtw;
	bool8 nd_onlink;
	int32 state;
        struct ifip6addr ipaddr; 
	int32 iface;
	

};

/* Destination Cache */
struct nd_descache
{
	byte nd_ip6dest[16];
	byte nd_ip6nexthop[16];
	uint32  nd_mtu;


};

/* Translation Table */
struct nat_translatetbl
{
	byte state;		//State of the entry - NAT_STATE_FREE, NAT_STATE_USED
	byte nat_packettype;	//Type of packet - ICMP or UDP
	byte nat_iplocal[16];	//Local IP addr in packet
	byte nat_iflocal;	//Interface of local packet
	uint16 nat_packetidlocal;	//Port no or Identifier in local net
	byte nat_ipremote[16];	//Remote Ip addr in packet
	uint16 nat_packetidremote;//Port no or Identifier outside local net
};


extern struct nat_translatetbl nattrans_tab[];
extern struct nd_routertbl ndroute_tab[];
extern struct nd_nbcentry nbcache_tab[];
