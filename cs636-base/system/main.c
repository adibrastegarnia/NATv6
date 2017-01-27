/*  main.c  - main */

#include <xinu.h>
#include <string.h>

process	main(void)
{

	/* Run the Xinu shell */

	recvclr();
	resume(create(shell, 8192, 2000, "shell", 1, CONSOLE));

	/* Wait for shell to exit and recreate it */

	/*byte *data = getmem(100);


	int i= 0;
	while(i < 20)
	{
	byte ip[]={0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x80, 0x0A, 0xFF, 0xFE, 0x88, 0x66,0x33};
	memcpy(data, ip, 16);
	icmp6_send(ip, ICMP6_ECHREQ_TYPE, 0, (void *)data, 100,1);

	i++;
	}*/
	while (TRUE) {
		receive();
		sleepms(200);
		kprintf("\n\nMain process recreating shell\n\n");
		resume(create(shell, 4096, 1000, "shell", 1, CONSOLE));
	}

	return OK;
    
}
