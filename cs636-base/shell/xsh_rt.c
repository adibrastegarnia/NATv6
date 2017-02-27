/* xsh_ps.c - xsh_ps */

#include <xinu.h>
#include <stdio.h>
#include <string.h>

/*------------------------------------------------------------------------
 * xsh_nc - shell command to print the process table
 *------------------------------------------------------------------------
 */
shellcmd xsh_rt(int nargs, char *args[])
{
	struct nd_routertbl *rtblptr ;		/* pointer to process		*/
	int32	i;			/* index into proctabl		*/
	char *pstate[]	= {		/* names for states	*/
		"free ", "used "};


	/* For argument '--help', emit help about the 'ps' command	*/

	if (nargs == 2 && strncmp(args[1], "--help", 7) == 0) {
		printf("Use: %s\n\n", args[0]);
		printf("Description:\n");
		printf("\tDisplays information about running processes\n");
		printf("Options:\n");
		printf("\t--help\t display this help and exit\n");
		return 0;
	}

	/* Check for valid number of arguments */

	if (nargs > 1) {
		fprintf(stderr, "%s: too many arguments\n", args[0]);
		fprintf(stderr, "Try '%s --help' for more information\n",
				args[0]);
		return 1;
	}
	
	if(host)	{
		kprintf("Not a NAT box!");
	}
	/* Print header for items from the process table */

	kprintf("\n%5s %5s %8s %6s %5s %6s %7s %7s %7s\n",
		   "Index", "Iface", "invatime", "defgtw", "State", "OnLink","preflen",  "IP Addr", "NPrefix");

	kprintf("%5s %5s %8s %6s %5s %7s %7s %7s %7s\n",
		   "-----", "-----", "--------", "------",
		   "-----", "-------", "-------", "-------", "-------");

	/* Output information for each entry */
	for(i=0; i < ND_ROUTETAB_SIZE; i++)
	{		
		rtblptr = &ndroute_tab[i];
		if (rtblptr ->state == RT_STATE_FREE) {  /* skip unused slots	*/
			continue;
		}

	kprintf("%d     %d     %d        %d      %s %d       %d  \n", i, rtblptr->iface, rtblptr->nd_invatime, rtblptr->nd_defgtw, pstate[(int)rtblptr->state], 			rtblptr->nd_onlink, rtblptr->ipaddr.preflen);

		ip6addr_print_ping(rtblptr->ipaddr.ip6addr);kprintf("   ");
		ip6addr_print_ping(rtblptr->nd_prefix);kprintf("   ");
		kprintf("\n");
	}

	return 0;
}
