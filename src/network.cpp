
#include <vector>
#include "network.h"

#ifdef WIN32
#include <winsock2.h>
#include <Windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

void get_netif_table(std::vector<netif_t> *out)
{
	std::vector<char> buffer;

	DWORD size = 0;

	if (GetIpAddrTable(NULL, &size, 0) == ERROR_INSUFFICIENT_BUFFER) {
		buffer.resize(size);
	}

	if (!buffer.empty()) {
		MIB_IPADDRTABLE *table = (MIB_IPADDRTABLE *)&buffer[0];
		if (GetIpAddrTable(table, &size, 0) == NO_ERROR) {
			if (table->dwNumEntries > 0) {
				for (DWORD i = 0; i < table->dwNumEntries; i++) {
					netif_t netif;
					netif.addr = ntohl(table->table[i].dwAddr);
					netif.mask = ntohl(table->table[i].dwMask);
					if (netif.addr == 0) continue;
					if (netif.addr == 0x7f000001) continue;
					if (netif.addr == 0x7f000101) continue;
					out->push_back(netif);
				}
			}
		}
	}
}

#else
#include <stdint.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>

void get_netif_table(std::vector<netif_t> *out)
{
	struct ifaddrs *ifa_list;
	if (getifaddrs(&ifa_list) == 0) {
		for (struct ifaddrs *ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr->sa_family == AF_INET) {
				netif_t netif;
				netif.addr = ntohl(*(uint32_t *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);
				netif.mask = ntohl(*(uint32_t *)&((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr);
				if (netif.addr == 0) continue;
				if (netif.addr == 0x7f000001) continue;
				if (netif.addr == 0x7f000101) continue;
				out->push_back(netif);
			} else if (ifa->ifa_addr->sa_family == AF_INET6) {
				// not implemented
			}
		}
		freeifaddrs(ifa_list);
	}
}

#endif


std::string get_host_name()
{
	char tmp[300];
	int i = sizeof(tmp) - 1;
	tmp[i] = 0;
	gethostname(tmp, i);
	return tmp;
}

