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

	kprintf("\n%4s, %20s, %40s\n", "State", "Prefix", "next hop" );

	kprintf("=====, =========================================, ===========================================\n");
	for(i=0; i < ND_ROUTETAB_SIZE; i++)
	{
		rtblptr = &ndroute_tab[i];
		
		if(rtblptr->state == RT_STATE_USED)
		{

			kprintf("%2d  ", rtblptr->state);
			ip6addr_print_ping(rtblptr->nd_prefix);
			kprintf("%4s", "  ");
			ip6addr_print_ping(rtblptr->ipaddr.ip6addr);

			kprintf("\n");
		}
		
	
		//printf("\n");


	}
	return 0;
}
