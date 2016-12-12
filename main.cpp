// STD includes
#include <iomanip>
#include <iostream>
#include <string>
#include <string.h>

// Project specific
#include <pcap.h>
#include <net/ethernet.h> // ethhdr
#include <arpa/inet.h> // inet_ntoa()
#include <netinet/ip_icmp.h>   //ip header
#include <netinet/tcp.h>   //tcp header

const int DEFAULT_ERROR_BUF_SIZE = 1024;
const int MAC_ADDR_OCTETS = 6;
#define NO_FLAGS        (!(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR))

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

    for(int i = 0; i < MAC_ADDR_OCTETS; i++)
        std::cout << std::hex
                  << std::setfill('0')
                  << std::setw(2)
                  << static_cast<int>(ethernetHeader->h_dest[i])
                  << (i == 5 ? "" : ":");

    std::cout << " ";

    for(int i = 0; i < MAC_ADDR_OCTETS; i++) {
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

    // nullify and place the source IP addr
    memset( &source, 0, sizeof(source) );
    source.sin_addr.s_addr = iph->saddr;

    // nullify and placethe dest IP addr
    memset( &destination, 0, sizeof(destination) );
    destination.sin_addr.s_addr = iph->daddr;

      // The inet_ntoa(addr) function converts the Internet host address addr,
    // given in network byte order, to a string in IPv4 dotted-decimal notation.
    std::cout << inet_ntoa( source.sin_addr );
    std::cout << " " << inet_ntoa( destination.sin_addr );
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

    // As the flags are 1 byte there is no endianess to check
    if( static_cast<uint8_t >(0) == tcph->th_flags )
    {
        type = "Null";
        return true;
    }
    else if( (TH_FIN + TH_PUSH + TH_URG) == tcph->th_flags )
    {
        type = "Xmas";
        return true;
    }

    return false;
}

bool
correct_tcp_checksum( const u_char* packet )
{
    // TODO: Check TCP checksum
    //IP header skipping the ethernet header
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

    // Ethernet header size is fixed, but IP header size is not
    size_t IPHeaderSize = iph->ihl*4;

    // TCP Header = packet + offset, where offset = length(eth) + length(iph)
    struct tcphdr *tcph = (struct tcphdr*)(packet + IPHeaderSize + sizeof(struct ethhdr));

    u_int16_t chksm = ntohs(tcph->check);

    // TODO: Calculate the real checksum
    u_int16_t real_chksm = chksm;

    return ( real_chksm == chksm );
}


// Check if the TCP packet satisfies some conditions and iff yes
// print information about it
void
print_tcp_packet( const u_char* packet,
                        int headerSize )
{
    // If the TCP checksum is not valid just bail
    if( !correct_tcp_checksum(packet) )
        return;

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

bool
correct_ip_checksum( struct iphdr* iph )
{
    u_int16_t chksm;
    chksm = ntohs(iph->check );
    size_t IPHeaderSize = iph->ihl*4;


    u_int16_t real_chksm = chksm;

    u_int16_t checksum = chksm;
    // Source : https://tools.ietf.org/html/rfc1071
    // TODO: Make it work work work

    /*
    register long sum = 0;
    int count = (int)IPHeaderSize;
    unsigned short* addr = (unsigned short*)iph;
    while( count > 1 )  {
        sum += *addr++;
        count -= 2;
    }

    if( count > 0 )
        sum += * (unsigned char *) addr;


    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    checksum = ~sum;

    */
    return checksum == chksm;
}

// Custom callback function called for processing every packet
void
handler(    u_char *userData, // not used
            const struct pcap_pkthdr* packetHeader,
            const u_char* packet )
{
    //IP header skipping the ethernet header
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

    // If the IP checksum is not correct just bail.
    // In this case we cannot even tell if the packet over it is TCP, UDP, etc.
    // Because the data is corrupted
    if( !correct_ip_checksum(iph))
        return;

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
