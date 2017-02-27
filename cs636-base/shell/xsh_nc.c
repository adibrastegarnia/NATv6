/* xsh_ps.c - xsh_ps */

#include <xinu.h>
#include <stdio.h>
#include <string.h>

/*------------------------------------------------------------------------
 * xsh_nc - shell command to print the process table
 *------------------------------------------------------------------------
 */
shellcmd xsh_nc(int nargs, char *args[])
{
	struct	nd_nbcentry *ncptr ;		/* pointer to process		*/
	int32	i;			/* index into proctabl		*/
	char *pstate[]	= {		/* names for states	*/
		"free ", "used "};
	char *rstate[]	= {		/* names for nc states	*/
		"free ", "inc ", "rea ", "sta ", "del ", "prob "};


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

	/* Print header for items from the process table */

	kprintf("\n%5s %8s %5s %6s %5s %6s %7s %7s %7s\n",
		   "Index", "IsRouter", "Iface", "NState", "Qcount", "RState", "Retries", "IP Addr", "HW Addr");

	kprintf("%5s %8s %5s %6s %5s %6s %7s %7s %7s\n",
		   "-----", "--------", "-----", "------", "-----",
		   "------", "-------", "-------", "-------");

	/* Output information for each process */
	for(i=0; i < ND_NCACHE_SIZE; i++)
	{

		ncptr = &nbcache_tab[i];
		if (ncptr->nc_state == PR_FREE) {  /* skip unused slots	*/
			continue;
		}
		kprintf("%d     %d        %d     %s   %d      %s       %d  ", i, ncptr->			nc_isrouter, ncptr->nc_iface, pstate[(int)ncptr->nc_state], 			ncptr->	nc_pqcount, rstate[(int)ncptr->nc_reachstate+1], ncptr->		nc_retries);
	
		kprintf("\n");
		ip6addr_print_ping(ncptr->nc_nbipucast);kprintf("   ");
		hwaddr_print_ping(ncptr->nc_hwaddr);kprintf("\n");

	}

	return 0;
}
