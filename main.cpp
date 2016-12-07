// STD includes
#include <iomanip>
#include <iostream>
#include <string>
#include <string.h>

// Project specific
#include <pcap.h>
#include <net/ethernet.h> // contains definition for ethhdr
#include <arpa/inet.h> // for inet_ntoa()
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
const int DEFAULT_ERROR_BUF_SIZE = 1024;
enum PROTOCOL
{
    ICMP = 1,
    IPV4 = 4,
    TCP  = 6,
    UDP  = 17
};

// Prints Source and Dest MAC addresses and ethernet type
void
process_ethernet_packet( const u_char* packet )
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

    std::cout << " ";
}

// Prints the Source and Dest IP addresses
void
process_ip_packet( const u_char* packet )
{
    struct sockaddr_in source, destination;

    // IP Header = packet + offset, where offset = length(ethernet header)
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr) );

    //
    memset( &source, 0, sizeof(source) );
    source.sin_addr.s_addr = iph->saddr;

    //
    memset( &destination, 0, sizeof(destination) );
    destination.sin_addr.s_addr = iph->daddr;

    // The inet_ntoa(addr) function converts the Internet host address addr,
    // given in network byte order, to a string in IPv4 dotted-decimal notation.
    std::cout
            << inet_ntoa( source.sin_addr )
            << " " << inet_ntoa( destination.sin_addr );
}

// Prints the protocol number, source and dest ports
void
process_tcp_packet( const u_char* packet )
{
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr) );

    // Ethernet header size is fixed, but IP header size is not
    size_t IPHeaderSize = iph->ihl*4;

    // TCP Header = packet + offset, where offset = length(eth) + length(iph)
    struct tcphdr *tcph = (struct tcphdr*)(packet + IPHeaderSize + sizeof(struct ethhdr));

    // The ntohs() function converts the unsigned short integer netshort
    // from network byte order to host byte order.
    std::cout
            << " " << static_cast<unsigned int>( iph->protocol ) // The protocol version, 6 equals to TCP
            << " " << std::dec << ntohs( tcph->source )
            << " " << std::dec << ntohs( tcph->dest );
}

// Returns true iff the packet flags are all null, or only FIN, PSH and URG are present
// Write to the 'type' string "Null", "Xmas" or nothing
bool
packet_xmas_or_null( const u_char* packet,
                     std::string& type )
{
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr) );

    // Ethernet header size is fixed, but IP header size is not
    size_t IPHeaderSize = iph->ihl*4;

    // TCP Header = packet + offset, where offset = length(eth) + length(iph)
    struct tcphdr *tcph = (struct tcphdr*)(packet + IPHeaderSize + sizeof(struct ethhdr));

    if( tcph->th_flags == 0 )
    {
        type = "Null";
        return true;
    }
    else if( tcph->th_flags == (TH_FIN + TH_PUSH + TH_URG) )
    {
        type = "Xmas";
        return true;
    }

    return false;
}


// Check if the TCP packet satisfies some conditions and iff yes
// print information about it
void
print_tcp_packet( const u_char* packet,
                        int headerSize )
{
    // If the TCP packet is not null or xmas return
    // otherwise proceed with processing and printing it
    std::string type;
    if( !packet_xmas_or_null( packet, type ))
        return;

    process_ethernet_packet( packet );
    process_ip_packet( packet );
    process_tcp_packet( packet);

    std::cout << " " << type << std::endl;
}

// Custom callback function called for processing every packet
void
handler(    u_char *userData, // not used
            const struct pcap_pkthdr* packetHeader,
            const u_char* packet )
{
    //IP header skipping the ethernet header
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

    // Implement via switch so it can be further improved for other protocols, too
    switch( iph->protocol ) {
        case TCP:
        {
            print_tcp_packet( packet, packetHeader->len );
            break;
        }
        default:
        {
            // do nothing
            break;
        }
    }
}

int
main(int argc, char* argv[])
{
    pcap_t* pcapDescriptor;
    char pcapErrorBuffer[DEFAULT_ERROR_BUF_SIZE];

    // Open for reading the .pcap file passed as first argument
    pcapDescriptor = pcap_open_offline( argv[1], pcapErrorBuffer );

    if(pcapDescriptor == NULL)
    {
        std::cerr<<"Error in pcap_open_offline. Content of error buffer: "
                 << pcapErrorBuffer << std::endl;
        return 1;
    }

    // pcap_loop is to process packets from a savefile
    // could also be used to process packets from a live capture
    // The most important part is the third argument, which is a callback function
    // with specific arguments, which cares to process the packets
    pcap_loop( pcapDescriptor, 0, handler, NULL );


    return 0;
}
