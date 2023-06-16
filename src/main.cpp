
// Bogons - The Bogus Name Service
// Copyright (C) 2017 S.Fuchita (@soramimi_jp)

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#endif

#include "bogons.h"
#include "network.h"

#include <string.h>


void apply_option(int argc, char **argv, bogons *dns)
{
	bogons::Mode mode = bogons::Mode::DNS;
	bool self = false;
	bool verbose = false;

	for (int i = 1; i < argc; i++) {
		char const *arg = argv[i];
		if (arg[0] == '-') {
			if (strcmp(arg, "-d") == 0 || strcmp(arg, "--dns") == 0) {
				mode = bogons::Mode::DNS;
			} else if (strcmp(arg, "-w") == 0 || strcmp(arg, "--wins") == 0) {
				mode = bogons::Mode::WINS;
			} else if (strcmp(arg, "-m") == 0 || strcmp(arg, "--mdns") == 0) {
				mode = bogons::Mode::MDNS;
			} else if (strcmp(arg, "-l") == 0 || strcmp(arg, "--llmnr") == 0) {
				mode = bogons::Mode::LLMNR;
			} else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--self") == 0) {
				self = true;
			} else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
				verbose = true;
			}
		}
	}

	dns->set_verbose(verbose);
	dns->set_mode(mode);
	if (self) {
		dns->update_names();
		dns->set_self_mode(true);
	}
}

int main(int argc, char **argv)
{
#ifdef WIN32
	{
		int r;
		WSADATA data;
		r = WSAStartup(MAKEWORD(1, 1), &data);
		if (r != 0) exit(1);
		atexit((void(*)(void))(WSACleanup));
	}
	std::string ini = "C:\\var\\bogons\\bogons.ini";
	std::string hosts = "C:\\var\\bogons\\hosts";
#else
	std::string ini = "/var/bogons/bogons.ini";
	std::string hosts = "/var/bogons/hosts";
#endif

	for (int retry = 0; retry < 60; retry++) {
		try {
			bogons dns(ini, hosts);
			apply_option(argc, argv, &dns);
			dns.main();
			break;
		} catch (std::string const &e) {
			fprintf(stderr, "%s\n", e.c_str());
		}
		sleep(1);
	}

	return 0;
}

