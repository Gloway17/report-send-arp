#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iostream>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

char* get_my_mac_address(const char *dev) {
    int sock;
    struct ifreq ifr;
    unsigned char mac[6];
    char* mac_str = (char*)malloc(18); // MAC 주소는 17글자 + null terminator

    if (mac_str == NULL) {
        perror("malloc");
        return NULL;
    }

    // 소켓 생성
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        free(mac_str);
        return NULL;
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    // MAC 주소 가져오기
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        free(mac_str);
        return NULL;
    }

    close(sock);

    // MAC 주소 변환
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return mac_str;  // 동적으로 할당된 MAC 주소 문자열 반환
}

char* get_ip_address(const char *dev) {
    int sock;
    struct ifreq ifr;
    char *ip_str = (char*)malloc(INET_ADDRSTRLEN);

    if (ip_str == NULL) {
        perror("malloc");
        return NULL;
    }

    // 소켓 생성
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        free(ip_str);
        return NULL;
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    // IP 주소 가져오기
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        free(ip_str);
        return NULL;
    }

    close(sock);

    // IP 주소를 문자열로 변환
    struct sockaddr_in* ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    inet_ntop(AF_INET, &ip_addr->sin_addr, ip_str, INET_ADDRSTRLEN);

    return ip_str;  // 동적으로 할당된 IP 주소 문자열 반환
}

void send_arp_request(pcap_t* handle, const char* dev, const char* ip) {
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(get_my_mac_address(dev));
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(get_my_mac_address(dev));
	packet.arp_.sip_ = htonl(Ip(get_ip_address(dev)));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

char* receive_arp_response() {
	while (true) {
		struct pcap_pkthdr* header;

		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);

		EthArpPacket *eth_arp = (EthArpPacket eth_arp*)packet;
		if (EthArpPacket.)

	}
}

int main(int argc, char* argv[]) {
	//std::cout << get_my_mac_address(argv[1]) << '\n';
	//std::cout << get_ip_address(argv[1]) << '\n';

	if (argc < 3) {
		usage();
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
		return -1;
	}

	// sender의 mac 주소 알아내기
	send_arp_request(pcap_t* handle, argv[1], argv[2])
	char sender_mac[] = receive_arp_response()

	// target의 mac 주소 알아내기
	send_arp_request(pcap_t* handle, argv[1], argv[2])
	char target_mac[] = receive_arp_response()

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac("00:00:00:00:00:00");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}