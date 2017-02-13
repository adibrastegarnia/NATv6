/* xsh_ps.c - xsh_ps */

#include <xinu.h>
#include <stdio.h>
#include <string.h>

/*------------------------------------------------------------------------
 * xsh_ps - shell command to print the process table
 *------------------------------------------------------------------------
 */
shellcmd xsh_route(int nargs, char *args[])
{

	int32 i;
	struct nd_routertbl *rtblptr;

	printf("%4s, %16s, %16s\n\n", "State", "Prefix", "next hop" );

	for(i=0; i < ND_ROUTETAB_SIZE; i++)
	{
		rtblptr = &ndroute_tab[i];
		
		printf("%4d ", rtblptr->state);
		ip6addr_print(rtblptr->nd_prefix);
		
		//ip6addr_print_ping(rtblptr->ipaddr.ip6addr);

		printf("\n");


	}
	return 0;
}
