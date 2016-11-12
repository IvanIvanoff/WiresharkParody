# WiresharkParody

0. Install libpcap-dev package
apt-get install libpcap-dev (On Debian/Ubuntu, should install its equivalent for other OS)

1. Compile with:
g++ main.cpp -o WParody -lpcap

2. Use it by passing a single argument .pcap file
 ./WParody sample.pcap

The program writes its output to the standart output stream. If you want to save the result to a file you could use:
./WParody sample.pcap > sampleResult.txt
