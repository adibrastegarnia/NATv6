/* dot2ip.c - dot2ip */

#include <xinu.h>

/*------------------------------------------------------------------------
 * dot2ip  -  Convert a string of dotted decimal to an unsigned integer
 *------------------------------------------------------------------------
 */
uint32	dot2ip (
	  char	 *dotted,		/* IP address in dotted decimal	*/
	  uint32 *result		/* Location to which binary IP	*/
					/*    address will be stored	*/
					/*    (host byte order)		*/
	)
{
	int32	seg;			/* Counts segments		*/
	int32	nch;			/* Counts chars within segment	*/
	char	ch;			/* Next character		*/
	uint32	ipaddr;			/* IP address in binary		*/
	int32	val;			/* Binary value of one segment	*/

	/* Input must have the form  X.X.X.X, where X is 1 to 3 digits	*/

	ipaddr = 0;
	for (seg=0 ; seg<4 ; seg++) {    /* For each segment		*/
	    val = 0;
	    for (nch=0 ; nch<4; nch++) { /* Up to four chars per segment*/
		ch = *dotted++;
		if ( (ch==NULLCH) || (ch == '.') ) {
			if (nch == 0) {
				return SYSERR;
			} else {
				break;
			}
		}

		/* Too many digits or non-digit is an error */

		if ( (nch>=3) || (ch<'0') || (ch>'9') ) {
			return SYSERR;
		}
		val = 10*val + (ch-'0');
	    }

	    if (val > 255) {	/* Out of valid range */
		return SYSERR;
	    }
	    ipaddr = (ipaddr << 8) | val;

	    if (ch == NULLCH) {
		break;
	    }
	}
	if ( (seg >= 4) || (ch != NULLCH) ) {
		return SYSERR;
	}
	*result = ipaddr;
	return OK;
}


/*------------------------------------------------------------------------
 * hex2ip  -  Convert a string of hexadecimal to an ipv6 addr array
 *------------------------------------------------------------------------
 */
uint32 hex2ip  (
	  char	 *hexaddr,		/* IP address in hexadecimal	*/
	  byte result[]			/* Location to which binary IP	*/
					/*    address will be stored	*/
					/*    (host byte order)		*/
	)
{

	int32	seg;			/* Counts segments		*/
	int32	nch;			/* Counts chars within segment	*/
	char	ch;			/* Next character		*/
	byte	ip6addr[16];		/* IP address in binary		*/
	int32	val;			/* Binary value of one segment	*/
	int32 i;
	/* Input must have the form  X:X:X:X:X:X:X:X, where X is 4 hexdigits	*/

	for(i=0;i<16; i++)	{
		ip6addr[i]= 0;
	}

	for (seg=0 ; seg<16 ; seg++) {    /* For each segment		*/
	    val = 0;
	    for (nch=0 ; nch<2; nch++) { /* Up to two chars per segment*/
		ch = *hexaddr++;
		if(ch == ':')
			ch = *hexaddr++;
		if(ch == NULLCH)
			break;

		/* Too many digits or non-hexdigit is an error */

		if ( (nch>=2) || (((ch<'0') || (ch>'9')) && !(((ch>='A')&&(ch<='F'))|| ((ch>='a')&&(ch<='f')))) ) {
			return SYSERR;
		}
		if(ch>='0' && ch<='9')
			val = 16*val + (ch-'0');
		else if(ch>='A' && ch<='F')
			val = 16*val + (ch-'A'+10);
		else
			val = 16*val + (ch-'a'+10);
		}
	    if (val > 255 ) {	/* Out of valid range */
			kprintf("Out of valid range index %d",seg );
			return SYSERR;
	    }
	    ip6addr[seg] = val;

	    if (ch == NULLCH) {
		break;
	    }
	}

	for(i=0;i<16;i++){		
		result[i] = ip6addr[i];
	}

	return OK;
}
