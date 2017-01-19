/* icmp.h - definintions for the Internet Control Message Protocol */


/* ICMPv6 message types */

#define ICMP6_ECHREQ_TYPE 128   /* Echo Request 	          */
#define ICMP6_ECHRES_TYPE 129   /* Echo Response 		  */
#define ICMP6_RSM_TYPE   133    /* Router Solicitation Message 	  */
#define ICMP6_RAM_TYPE   134    /* Router Advertisement Message   */
#define ICMP6_NSM_TYPE   135    /* Neighbor Solicitation Message  */ 
#define ICMP6_NAM_TYPE   136    /* Neighbor Advertisement Message */
#define ICMP6_RDM_TYPE   137    /* Redirect Message 		  */








#define	ICMP_SLOTS	10		/* num. of open ICMP endpoints	*/
#define	ICMP_QSIZ	8		/* incoming packets per slot	*/

/* Constants for the state of an entry */

#define	ICMP_FREE	0		/* entry is unused		*/
#define	ICMP_USED	1		/* entry is being used		*/
#define	ICMP_RECV	2		/* entry has a process waiting	*/

#define ICMP_HDR_LEN	8		/* bytes in an ICMP header	*/

/* ICMP message types for ping */

#define	ICMP_ECHOREPLY	0		/* ICMP Echo Reply message	*/
#define ICMP_ECHOREQST	8		/* ICMP Echo Request message	*/

/* table of processes that are waiting for ping replies */

struct	icmpentry {			/* entry in the ICMP table	*/
	int32	icstate;		/* state of entry: free/used	*/
	uint32	icremip;		/* remote IP address		*/
	int32	ichead;			/* index of next packet to read	*/
	int32	ictail;			/* index of next slot to insert	*/
	int32	iccount;		/* count of packets enqueued	*/
	pid32	icpid;			/* ID of waiting process	*/
	struct	netpacket *icqueue[ICMP_QSIZ];/* circular packet queue	*/
};

extern	struct	icmpentry icmptab[];	/* table of UDP endpoints	*/
