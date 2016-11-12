#include <pcap.h>
#include <net/ethernet.h> // contains definition for ethhdr
#include <iostream>
#include <iomanip>
#include <arpa/inet.h>

const int DEFAULT_ERROR_BUF_SIZE = 1024;

void
handler( u_char *userData, // not used
         const struct pcap_pkthdr* packetHeader, // not used
         const u_char* packet )
{
    struct ethhdr *ethernetHeader = (struct ethhdr *)packet;

    for(int i = 0; i<=5; i++)
        std::cout << std::hex
                  << std::setfill('0')
                  << std::setw(2)
                  << static_cast<int>(ethernetHeader->h_dest[i])
                  << (i == 5 ? "" : ":");

    std::cout << " ";

    for(int i = 0; i <=5; i++) {
        std::cout << std::hex
                  << std::setfill('0')
                  << std::setw(2)
                  << static_cast<int>(ethernetHeader->h_source[i])
                  << (i == 5 ? "" : ":");
    }
    std::cout << " 0x"
              << std::hex
              << std::setfill('0')
              << std::setw(4)
              << ntohs( static_cast<int>(ethernetHeader->h_proto) );

    std::cout << std::endl;
}

int
main(int argc, char* argv[])
{
    pcap_t* pcapDescriptor;
    char pcapErrorBuffer[DEFAULT_ERROR_BUF_SIZE];

    pcapDescriptor = pcap_open_offline(argv[1], pcapErrorBuffer);

    if(pcapDescriptor == NULL)
    {
        std::cerr<<"Error in pcap_open_offline. Content of error buffer: "
                 << pcapErrorBuffer << std::endl;
        return 1;
    }

    pcap_loop( pcapDescriptor, 0, handler, NULL );


    return 0;
}

