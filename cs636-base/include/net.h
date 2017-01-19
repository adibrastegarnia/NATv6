/* net.h */

#define NETSTK		8192 		/* Stack size for network setup */
#define NETPRIO		500    		/* Network startup priority 	*/

/* Constants used in the networking code */

#define	ETH_ARP     0x0806		/* Ethernet type for ARP	*/
#define	ETH_IP      0x0800		/* Ethernet type for IP		*/
#define	ETH_IPv6    0x86DD		/* Ethernet type for IPv6	*/

#define	OTH_ADDR_LEN	ETH_ADDR_LEN	/* Othernet address size	*/



struct ifip6addr {
	byte ip6addr[16];
	uint32 preflen;

};

struct ifip6nmcast{
	byte if_ip6nwmcast[6];
};


/* Format of an Ethernet or Othernet packet */

#pragma pack(2)
struct	netpacket	{
	byte	net_dst[ETH_ADDR_LEN];	/* Destination MAC address	*/
	byte	net_src[ETH_ADDR_LEN];	/* Source MAC address		*/
	uint16	net_type;		/* Layer 2 type field		*/

	union
	{
		byte   net_payload[1500];               /* Ethernet Payload */
		struct {		
			byte   net_ip6ver;              /* IPv6 version 		*/
			byte   net_ip6tc;               /* IPv6 traffic class 		*/
			uint16 net_ip6fll;               /* IPv6 flow label 		*/  
			uint16 net_ip6len;              /* IPv6 payload length 		*/
			byte   net_ip6nh;                /* IPv6 next header 		*/
			byte   net_ip6hl;		/* IPv6 hop limit 		*/
			byte   net_ip6src[16];		/* IPv6 source address 		*/
			byte   net_ip6dst[16];		/* IPv6 destination address 	*/
			union {
				byte  net_ipdata[1500 - 40];

				/* ICMPv6 data strucutre */ 
				struct {
					byte net_ictype; 		/* IPv6 ICMP type 		*/ 
					byte net_iccode;		/* IPv6 ICMP code 		*/
					uint16 net_icchksm;  		/* IPv6 ICMP check sum  	*/
					byte   net_icdata[1500 - 58];  	/*  IPv6 ICMP payload   	*/
				};

				/* UDP data strucutre   */
				struct {
					uint16 net_udpsrcport;  	/* IPv6 UDP source port 	*/
					uint16 net_udpdstport;  	/* IPv6 UDP destination port 	*/
					uint16 net_udplen;    		/* IPv6 UDP length		*/ 		
					uint16 net_udpchksm;     	/* IPv6 UDP checksum 		*/
					byte   net_udpdata[1500-62];    /* IPv6 UDP payload 		*/
				};
			};
		};
	};

        int16	net_iface;		/* Interface over which the	*/
	

};
#pragma pack()

#define	PACKLEN	sizeof(struct netpacket)

extern	bpid32	netbufpool;		/* ID of net packet buffer pool	*/



/* Definintions for network interfaces (used by IP) */

#define	NIFACES	3		/* Number of interfaces -- one for the	*/
				/*   Ethernet plus two "othernets"	*/

/* Interface state definitions */

#define	IF_UP		1	/* Interface is currently on line	*/
#define	IF_DOWN		0	/* Interface is currently offline	*/

#define	IF_QUEUESIZE	20	/* Size of the incoming packet queue	*/
				/*   for each interface			*/

#define	IF_NLEN		32	/* Max characters in an interface name	*/

#define IF_MAX_NUCAST   5       /* Max number of unicast addresses for IPv6   */ 
#define IF_MAC_NMCAST   5       /* Max number of multicast addresses for IPv6 */

/* Network interface structure */

struct	ifentry	{
	char	if_name[IF_NLEN];/* Name for the interface		*/
	bool8	if_state;	/* Interface is either up or down	*/
	did32	if_dev;		/* Device ID of the layer2 device used	*/
				/*    with this interface		*/
	byte	if_macucast[ETH_ADDR_LEN]; /* MAC unicast address	*/
	byte	if_macbcast[ETH_ADDR_LEN]; /* MAC broadcast address	*/
	sid32	if_sem;		/* semaphore counts incoming packets	*/
				/*    in the queue			*/

	struct	netpacket *if_queue[IF_QUEUESIZE]; /* queue to hold	*/
				/*  incoming packets for this interface	*/
	int32	if_head;	/* next entry in packet queue to remove	*/
	int32	if_tail;	/* next slot in packet queue to insert	*/

	/* *** NOTE ADDITIONAL IPv4/IPv6/ARP/ND fields go here *** */
	struct ifip6addr if_ip6ucast[IF_MAX_NUCAST];   /* IPv6 unicast address 	 */
	struct ifip6addr if_ip6mcast[IF_MAC_NMCAST];   /* IPv6 multicast address */
	struct ifip6nmcast if_ip6newmcast[IF_MAX_NUCAST];

	int32 if_nipmcast;
	int32 if_nipucast;
	
};

extern	struct	ifentry	if_tab[];

extern	int32	ifprime;	/* Primary interface.  For a host, the	*/
				/*   only interface that's up, for a	*/
				/*   nat box, interface 0.  -1 means	*/
				/*   no network is active.		*/
extern	bool8	host;		/* TRUE if this node is running as a	*/
				/*   host; FALSE if acting as a NAT box	*/
extern	int32	bingid;		/* User's bing ID			*/
