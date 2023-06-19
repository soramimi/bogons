
// Bogons - The Bogus Name Service
// Copyright (C) 2023 S.Fuchita (@soramimi_jp)

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

struct Option {
	bool daemon = false;
};

void apply_option(int argc, char **argv, bogons *ns, Option *opt)
{
	bogons::Mode mode = bogons::Mode::DNS;
	bool self = false;
	bool verbose = false;
	*opt = {};

	for (int i = 1; i < argc; i++) {
		char const *arg = argv[i];
		if (arg[0] == '-') {
			if (strcmp(arg, "-D") == 0 || strcmp(arg, "--daemon") == 0) {
				opt->daemon = true;
			} else if (strcmp(arg, "-d") == 0 || strcmp(arg, "--dns") == 0) {
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

	ns->set_verbose(verbose);
	ns->set_mode(mode);
	if (self) {
		ns->update_names();
		ns->set_self_mode(true);
	}
}

int main2(bogons *ns, Option *opt)
{
	auto Perform = [&](){
		try {
			ns->main();
		} catch (std::string const &e) {
			fprintf(stderr, "%s\n", e.c_str());
		}
	};

#ifdef WIN32
#else
	if (opt->daemon) {
		if (daemon(0, 0) != 0) {
			fprintf(stderr, "daemon() failed\n");
			return 1;
		}
		while (1) {
			Perform();
			sleep(1);
		}
	}
#endif

	Perform();
	return 0;
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

	bogons ns(ini, hosts);
	Option opt;
	apply_option(argc, argv, &ns, &opt);
	main2(&ns, &opt);

	return 0;
}

