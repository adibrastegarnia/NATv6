/* ip.h  -  Constants related to Internet Protocol version 4 (IPv4) */


/* IPv6 Extension headers type */

#define IP6_EXT_HBH   		0     /* Hop by Hop options  		*/
#define IP6_EXT_DO    		60    /* Destination options 		*/
#define IP6_EXT_ROUTING 	43    /* Routing 	     		*/
#define IP6_EXT_FRAGMENT 	44    /* Fragment 	     		*/
#define IP6_EXT_AH       	51    /* Authentication Header  	*/
#define IP6_EXT_ESP     	50    /* Encapsulation Securtiy Payload */
#define IP6_EXT_ICMP            58    /* ICMPv6  			*/
#define IP6_EXT_UDP             17    /* UDPv6 				*/
#define IP6_EXT_TCP             6     /* TCPv6 				*/
#define IP6_EXT_NOHDR           59    /* No extension header 		*/









#define	IP_BCAST	0xffffffff	/* IP local broadcast address	*/
#define	IP_THIS		0xffffffff	/* "this host" src IP address	*/
#define	IP_ALLZEROS	0x00000000	/* The all-zeros IP address     */

#define	IP_ICMP		1		/* ICMP protocol type for IP 	*/
#define	IP_UDP		17		/* UDP protocol type for IP 	*/

#define	IP_ASIZE	4		/* Bytes in an IP address	*/
#define	IP_HDR_LEN	20		/* Bytes in an IP header	*/
#define IP_VH		0x45 		/* IP version and hdr length 	*/

#define	IP_OQSIZ	8		/* Size of IP output queue	*/

/* Queue of outgoing IP packets waiting for ipout process */

struct	iqentry	{
	int32	iqhead;			/* Index of next packet to send	*/
	int32	iqtail;			/* Index of next free slot	*/
	sid32	iqsem;			/* Semaphore that counts pkts	*/
	struct	netpacket *iqbuf[IP_OQSIZ];/* Circular packet queue	*/
};

extern	struct	iqentry	ipoqueue;	/* Network output queue		*/


#define IP_ICMP6   58                  /* ICMP Protocol type for IPv6   */

extern byte ip6_ulapref[];

/* IP Link-local prefix */
extern byte	ip6_llpref[];


/* Solicited-node Multicast prefix */
extern byte    ip6_nd_snmpref[];


/* Unspecified IP address */
extern byte ip6_unspec[16];


/* All nodes IPv6 Multicast address */

extern byte ip6_allnodesmc[16];

/* All routers multicast IPv6 address */
extern byte ip6_allroutermc[16];

/* IPv6 Extension header strucutre */
struct ip6_ext_hdr
{
	byte ip6ext_nh;    /* Next header 	*/
	byte ip6ext_len;   /* Header length 	*/

	union
	{
		/* Routing header */
		struct {
			byte ip6_rhtype;
			byte ip6_segleft;



		};

	};


};

/* IPv6 pseudo header */
#pragma pack(1)
struct pseudo {
	byte ip6_src[16];
	byte ip6_dst[16];
	uint32 pktlen;
	byte zeros[3];
	byte ipnh;

};
#pragma pack()



/* Check IPv6 address is mutlicast or not */
#define	isipmc(x)	((*(x)) == 0xff)
/* Check IPv6 address is link local address or not */
#define	isipllu(x)	(!memcmp((x), ip6_llpref, 8))

/* Check IPv6  address an unspecified address or not */
#define	isipunspec(x) (!memcmp((x), ip6_unspec, 16))



/* Check IPv6 address is unique local address */
#define isipula(x)    ((*(x)) == 0xfd)


