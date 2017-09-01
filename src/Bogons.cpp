#include "Bogons.h"

#include "network.h"
#include "rwfile.h"

#include <time.h>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
static inline std::string STRERROR(std::string const &s)
{
	char *p = 0;
	DWORD lang;
	if (1) {
		lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
	} else {
		lang = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
	}
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 0, GetLastError(), lang, (LPSTR)&p, 0, 0);
	std::string r = s;
	if (p) {
		r += p;
		LocalFree(p);
	}
	return r;
}

#else // not WIN32
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#define stricmp(A, B) strcasecmp(A, B)
#define STRERROR(S) (std::string(S) + strerror(errno))
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket(S) close(S)
#endif

#include <sys/stat.h>

#define DNS_TYPE_A 1
#define DNS_TYPE_PTR 12
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_NB 32

#define DNS_CLASS_IN 1

struct Bogons::dns_a_record_t {
	uint32_t addr;
};

struct Bogons::dns_header_t {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

struct Bogons::query_t {
	uint16_t upstream_id;
	uint16_t requester_id;
	time_t time;
	uint16_t type;
	sockaddr_in peer;
	std::string name;
};

struct Bogons::question_t {
	std::string name;
	uint16_t type;
	uint16_t clas;
};

struct Bogons::answer_t {
	std::string name;
	uint16_t type;
	uint16_t clas;
	uint32_t ttl;
	std::vector<char> data;
};

struct Bogons::name_map_t {
	struct less_t {
		bool operator () (std::string const &left, std::string const &right) const
		{
			return stricmp(left.c_str(), right.c_str()) < 0;
		}
	};
	std::map<std::string, dns_a_record_t, less_t> map;
};

struct Bogons::Private {
	std::string hostsfile;
	time_t hoststime;

	Mode mode;

	bool self_mode;
	std::string my_host_name;
	std::string my_host_name_local;
	std::vector<netif_t> netif_table;
	time_t netif_timestamp = 0;

	int ttl;

	std::map<std::string, std::string> ini;
	name_map_t dns_a_map;
	uint16_t next_transaction_id;
	std::vector<query_t> queries;

	uint32_t upstream_server;

	bool verbose;
};

Bogons::Bogons(const std::string &inifile, const std::string &hostsfile)
{
	pv = new Private();
	pv->verbose = false;
	pv->hostsfile = hostsfile;
	pv->mode = Mode::DNS;
	pv->self_mode = false;
	parse_ini_file(inifile.c_str(), &pv->ini);
	read_hosts_file();
	init_ttl();
	init_upstream_server();
}

Bogons::~Bogons()
{
	delete pv;
}

void Bogons::set_verbose(bool f)
{
	pv->verbose = f;
}

void Bogons::set_mode(Mode mode)
{
	pv->mode = mode;
}

bool Bogons::is_self_mode() const
{
	return pv->self_mode;
}

void Bogons::set_self_mode(bool f)
{
	pv->self_mode = f;
}

void Bogons::update_netif_table()
{
	time_t t = time(nullptr);
	if (pv->netif_timestamp < t) {
		pv->netif_timestamp = t + 10;
		if (pv->my_host_name.empty()) {
			pv->netif_table.clear();
		} else {
			get_netif_table(&pv->netif_table);
		}
	}
}

void Bogons::set_hostname(const std::string &name)
{
	pv->my_host_name = name;
	pv->my_host_name_local = name + ".local";
	update_netif_table();
}

bool Bogons::eqi(const std::string &l, const std::string &r)
{
	return stricmp(l.c_str(), r.c_str()) == 0;
}

bool Bogons::verbose() const
{
	return pv->verbose;
}

bool Bogons::isDNS() const
{
	return pv->mode == Mode::DNS;
}

bool Bogons::isMDNS() const
{
	return pv->mode == Mode::MDNS;
}

bool Bogons::isWINS() const
{
	return pv->mode == Mode::WINS;
}

bool Bogons::isLLMNR() const
{
	return pv->mode == Mode::LLMNR;
}

uint16_t Bogons::port() const
{
	switch (pv->mode) {
	case Mode::MDNS:  return 5353;
	case Mode::WINS:  return 137;
	case Mode::LLMNR: return 5355;
	}
	return 53;
}

int Bogons::ttl() const
{
	return pv->ttl;
}

void Bogons::write(std::vector<char> *out, char c)
{
	out->push_back(c);
}

void Bogons::write(std::vector<char> *out, const char *src, int len)
{
	if (src && len > 0) {
		out->insert(out->end(), src, src + len);
	}
}

void Bogons::write_us(std::vector<char> *out, uint16_t v)
{
	v = htons(v);
	write(out, (char const *)&v, 2);
}

void Bogons::write_ul(std::vector<char> *out, uint32_t v)
{
	v = htonl(v);
	write(out, (char const *)&v, 4);
}

void Bogons::write_name(std::vector<char> *out, const std::string &name)
{
	char const *name_begin = name.c_str();
	char const *name_end = name_begin + name.size();
	char const *srcptr = name_begin;
	while (srcptr < name_end) {
		char const *dot = strchr(srcptr, '.');
		int len = (dot ? dot : name_end) - srcptr;
		if (len < 1 || len > 63) {
			return;
		}
		write(out, (char)len);
		write(out, srcptr, len);
		if (!dot) {
			break;
		}
		srcptr += len + 1;
	}
	write(out, (char)0);
}

int Bogons::decode_name(const char *begin, const char *end, const char *ptr, std::vector<char> *out)
{
	if (begin && ptr && begin <= ptr && ptr < end) {
		char const *start = ptr;
		if ((*ptr & 0xc0) == 0xc0) {
			if (ptr + 1 < end) {
				int o = ((ptr[0] & 0x3f) << 8) | (ptr[1] & 0xff);
				decode_name(begin, end, begin + o, out);
				ptr += 2;
			}
		} else {
			while (ptr < end) {
				int len = *ptr & 0xff;
				ptr++;
				if (len == 0 || len > 63) {
					break;
				}
				if (!out->empty()) {
					out->push_back('.');
				}
				out->insert(out->end(), ptr, ptr + len);
				ptr += len;
			}
		}
		if (ptr < start || ptr > end) {
			ptr = end;
		}
		return ptr - start;
	}
	return 0;
}

int Bogons::decode_name(const char *begin, const char *end, const char *ptr, std::string *name)
{
	std::vector<char> tmp;
	tmp.reserve(100);
	int n = decode_name(begin, end, ptr, &tmp);
	if (n > 0 && !tmp.empty()) {
		char const *p = &tmp[0];
		*name = std::string(p, p + tmp.size());
		return n;
	}
	return 0;
}

void Bogons::split(const char *begin, const char *end, std::vector<std::string> *out)
{
	out->clear();
	char const *ptr = begin;
	char const *left = ptr;
	while (1) {
		int c = -1;
		if (ptr < end) {
			c = *ptr & 0xff;
		}
		if (isspace(c) || c < 0) {
			if (left < ptr) {
				std::string s(left, ptr - left);
				out->push_back(s);
			}
			if (c < 0) {
				break;
			}
			left = ptr + 1;
		}
		ptr++;
	}
}

std::string Bogons::trimmed(const char *left, const char *right)
{
	while (left < right && isspace(*left & 0xff)) left++;
	while (left < right && isspace(right[-1] & 0xff)) right--;
	return std::string(left, right);
}

void Bogons::parse_ini_file(const char *path, std::map<std::string, std::string> *out)
{
	out->clear();

	std::vector<char> vec;
	readfile(path, &vec);

	if (!vec.empty()) {
		char const *begin = &vec[0];
		char const *end = begin + vec.size();
		char const *ptr = begin;
		char const *left = ptr;
		while (1) {
			int c = -1;
			if (ptr < end) {
				c = *ptr & 0xff;
			}
			if (c == '\n' || c == '\r' || c < 0) {
				char const *right = ptr;
				if (c == '\n') {
					ptr++;
				} else if (c == '\r') {
					ptr++;
					if (ptr < end && *ptr == '\n') {
						ptr++;
					}
				}
				while (left < right && isspace(*left & 0xff)) {
					left++;
				}
				if (left < right && *left != '#') {
					for (char const *eq = left; eq < right; eq++) {
						if (*eq == '=') {
							std::string key = trimmed(left, eq);
							std::string val = trimmed(eq + 1, right);
							(*out)[key] = val;
							break;
						}
					}
				}
				if (c < 0) {
					break;
				}
				left = ptr;
			}
			ptr++;
		}
	}
}

void Bogons::parse_hosts_file(const char *path, Bogons::name_map_t *out)
{
	out->map.clear();

	std::vector<char> vec;
	readfile(path, &vec);

	if (!vec.empty()) {
		char const *begin = &vec[0];
		char const *end = begin + vec.size();
		char const *ptr = begin;
		char const *left = ptr;
		while (1) {
			int c = -1;
			if (ptr < end) {
				c = *ptr & 0xff;
			}
			if (c == '\n' || c == '\r' || c < 0) {
				char const *right = ptr;
				if (c == '\n') {
					ptr++;
				} else if (c == '\r') {
					ptr++;
					if (ptr < end && *ptr == '\n') {
						ptr++;
					}
				}
				while (left < right && isspace(*left & 0xff)) left++;
				while (left < right && isspace(right[-1] & 0xff)) right--;
				if (left < right && *left != '#') {
					std::vector<std::string> arr;
					split(left, right, &arr);
					if (arr.size() > 1) {
						unsigned int a, b, c, d;
						if (sscanf(arr[0].c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
							if (a < 256 && b < 256 && c < 256 && d < 256) {
								dns_a_record_t item;
								item.addr = (a << 24) | (b << 16) | (c << 8) | d;
								for (int i = 1; i < (int)arr.size(); i++) {
									std::string name = arr[i];
									if (!name.empty()) {
										out->map[name] = item;
									}
								}
							}
						}
					}
				}
				if (c < 0) {
					break;
				}
				left = ptr;
			}
			ptr++;
		}
	}
}

time_t Bogons::get_hosts_time()
{
	struct stat st;
	if (stat(pv->hostsfile.c_str(), &st) == 0) {
		return st.st_mtime;
	}
	return 0;
}

void Bogons::read_hosts_file()
{
	pv->hoststime = get_hosts_time();
	parse_hosts_file(pv->hostsfile.c_str(), &pv->dns_a_map);
}

void Bogons::write_dns_header(std::vector<char> *out, uint16_t id, uint16_t flags, uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount)
{
	uint16_t tmp[6];
	tmp[0] = htons(id);
	tmp[1] = htons(flags);
	tmp[2] = htons(qdcount);
	tmp[3] = htons(ancount);
	tmp[4] = htons(nscount);
	tmp[5] = htons(arcount);
	write(out, (char const *)tmp, 12);
}

void Bogons::write_dns_question_rr(std::vector<char> *out, const std::string &name, uint16_t type, uint16_t clas)
{
	write_name(out, name);
	write_us(out, type);
	write_us(out, clas);
}

void Bogons::write_dns_answer_rr(std::vector<char> *out, const std::string &name, uint16_t type, uint16_t clas, uint32_t ttl, const Bogons::dns_a_record_t &item)
{
	uint32_t addr = htonl(item.addr);
	write_name(out, name);
	write_us(out, type);
	write_us(out, clas);
	write_ul(out, ttl);
	write_us(out, 4);
	write(out, (char const *)&addr, 4);
}

void Bogons::write_wins_rr(std::vector<char> *out, const std::string &name, uint16_t type, uint16_t clas, uint32_t ttl, uint16_t nameflags, const Bogons::dns_a_record_t &item)
{
	uint32_t addr = htonl(item.addr);
	write_name(out, name);
	write_us(out, type);
	write_us(out, clas);
	write_ul(out, ttl);
	write_us(out, 6);
	write_us(out, nameflags);
	write(out, (char const *)&addr, 4);
}

int Bogons::parse_question_section(const char *begin, const char *end, const char *ptr, Bogons::question_t *out)
{
	int n = decode_name(begin, end, ptr, &out->name);
	if (n > 0 && !out->name.empty()) {
		char const *start = ptr;
		ptr += n;
		uint16_t tmp[2];
		memcpy(tmp, ptr, 4);
		ptr += 4;
		out->type = ntohs(tmp[0]);
		out->clas = ntohs(tmp[1]);
		return ptr - start;
	}
	return 0;
}

bool Bogons::get_ini_string(const std::string &name, std::string *out) const
{
	std::map<std::string, std::string>::const_iterator it = pv->ini.find(name);
	if (it != pv->ini.end()) {
		if (out) {
			*out = it->second;
		}
		return true;
	}
	return false;
}

std::string Bogons::get_ini_string(const std::string &name, const std::string &def) const
{
	std::string s;
	if (get_ini_string(name, &s)) {
		return s;
	}
	return def;
}

uint32_t Bogons::get_upstream_server()
{
	return pv->upstream_server;
}

uint32_t Bogons::get_addr_by_name(const char *name)
{
	if (!name) return 0;
	if (!*name) return 0;
#if 0
	return inet_addr(name);
#elif 1
	struct hostent *h = gethostbyname(name);
	if (h) {
		return *(uint32_t *)h->h_addr;
	}
	return 0;
#else
	struct addrinfo hints;
	struct addrinfo *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	if (getaddrinfo(name, 0, &hints, &res) == 0) {
		uint32_t a = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
		freeaddrinfo(res);
		return a;
	}
	return 0;
#endif
}

void Bogons::init_upstream_server()
{
	std::string s = get_ini_string("masterserver");
	uint32_t a = get_addr_by_name(s.c_str());
	if (a != 0 && a != INADDR_NONE) {
		pv->upstream_server = ntohl(a);
	} else {
		pv->upstream_server = 0;
	}
}

void Bogons::cleanup()
{
	time_t now = time(0);
	size_t i = pv->queries.size();
	while (i > 0) {
		i--;
		if (pv->queries[i].time - now > 2) {
			pv->queries.erase(pv->queries.begin() + i);
		}
	}
}

bool Bogons::take_query(uint16_t id, Bogons::query_t *out)
{
	bool ok = false;
	size_t i = pv->queries.size();
	while (i > 0) {
		i--;
		query_t const &q = pv->queries[i];
		if (id == q.upstream_id) {
			if (out) {
				*out = q;
				out = 0;
				ok = true;
			}
			pv->queries.erase(pv->queries.begin() + i);
		}
	}
	return ok;
}

void Bogons::delete_pending_query(uint16_t id)
{
	query_t q;
	take_query(id, &q);
}

void Bogons::push_query(const Bogons::query_t &query)
{
	take_query(query.upstream_id, 0);
	pv->queries.push_back(query);
}

std::string Bogons::decode_netbios_name(const std::string &name, int *restype)
{
	int n = name.size() / 2;
	if (n > 16) n = 16;
	int i;
	unsigned char tmp[16];
	for (i = 0; i < n; i++) {
		char h = name[i * 2 + 0];
		char l = name[i * 2 + 1];
		if (h >= 'A' && h <= 'P' && l >= 'A' && l <= 'P') {
			unsigned char c = ((h - 'A') << 4) | (l - 'A');
			tmp[i] = c;
		}
	}
	if (i > 1) {
		i--;
		*restype = tmp[i];
		while (i > 0 && isspace(tmp[i - 1])) i--;
		return std::string((char const *)tmp, i);
	}
	*restype = -1;
	return std::string();
}

bool Bogons::get_my_address(uint32_t srcaddr, Bogons::dns_a_record_t *out)
{
	update_netif_table();
	std::vector<netif_t> const *table = &pv->netif_table;
	for (std::vector<netif_t>::const_iterator it = table->begin(); it != table->end(); it++) {
		netif_t const &netif = *it;
		if ((netif.addr & netif.mask) == (srcaddr & netif.mask)) {
			out->addr = netif.addr;
			return true;
		}
	}
	return false;
}

void Bogons::make_response(const Bogons::dns_header_t &header, const Bogons::question_t &q, const Bogons::dns_a_record_t &r, std::vector<char> *out)
{
	if ((isDNS() || isLLMNR()) && q.type == DNS_TYPE_A) {
		uint16_t flags = 0x8180;
		if (isLLMNR()) {
			flags = 0x8000;
		}
		write_dns_header(out, header.id, flags, 1, 1, 0, 0);
		write_dns_question_rr(out, q.name, q.type, q.clas);
		write_dns_answer_rr(out, q.name, q.type, q.clas, ttl(), r);
	} else if (isWINS() && q.type == DNS_TYPE_NB) {
		uint16_t nameflags = 0;
		write_dns_header(out, header.id, 0x8580, 0, 1, 0, 0);
		write_wins_rr(out, q.name, q.type, q.clas, ttl(), nameflags, r);
	} else if (isMDNS() && q.type == DNS_TYPE_A) {
		write_dns_header(out, header.id, 0x8500, 1, 1, 0, 0);
		write_dns_question_rr(out, q.name, q.type, q.clas);
		write_dns_answer_rr(out, q.name, q.type, q.clas, ttl(), r);
	}
}

void Bogons::init_ttl()
{
	pv->ttl = 0;
	std::string s;
	if (get_ini_string("ttl", &s)) {
		pv->ttl = atoi(s.c_str());
	}
	if (pv->ttl < 1) {
		pv->ttl = 60;
	}
}

std::string Bogons::stripv4(uint32_t a)
{
	char tmp[20];
	sprintf(tmp, "%u.%u.%u.%u"
			, (a >> 24) & 0xff
			, (a >> 16) & 0xff
			, (a >> 8) & 0xff
			, a & 0xff
			);
	return tmp;
}

void Bogons::parse_response(const char *begin, const char *end, Bogons::dns_header_t *header, std::list<Bogons::question_t> *questions, std::list<Bogons::answer_t> *answers)
{
	char const *ptr = begin;

	header->id = ntohs(*(uint16_t *)&ptr[0]);
	header->flags = ntohs(*(uint16_t *)&ptr[2]);
	header->qdcount = ntohs(*(uint16_t *)&ptr[4]);
	header->ancount = ntohs(*(uint16_t *)&ptr[6]);
	header->nscount = ntohs(*(uint16_t *)&ptr[8]);
	header->arcount = ntohs(*(uint16_t *)&ptr[10]);
	ptr += 12;

	std::vector<char> res;

	for (int i = 0; i < header->qdcount; i++) {
		question_t q;
		int n = parse_question_section(begin, end, ptr, &q);
		if (n > 0 && !q.name.empty()) {
			ptr += n;
			questions->push_back(q);
		}
	}

	for (int i = 0; i < header->ancount; i++) {
		answer_t a;
		int n = decode_name(begin, end, ptr, &a.name);
		if (n > 0 && !a.name.empty()) {
			ptr += n;
		}
		if (ptr + 10 <= end) {
			uint16_t tmp[5];
			memcpy(tmp, ptr, 10);
			a.type = ntohs(tmp[0]);
			a.clas = ntohs(tmp[1]);
			a.ttl = ntohl(*(uint32_t *)&tmp[2]);
			uint16_t rdlen = ntohs(tmp[4]);
			ptr += 10;
			if (ptr + rdlen <= end) {
				std::list<answer_t>::iterator it = answers->insert(answers->end(), answer_t());
				*it = a;
				it->data.resize(rdlen);
				memcpy(&it->data[0], ptr, rdlen);
				ptr += rdlen;
			}
		}
	}
}

void Bogons::main()
{
	pv->next_transaction_id = 0;

	if (verbose()) {
		printf("Boguns - The Bogus Name Service\n\n");

		char const *mode = "DNS(UDP/53)";
		switch (pv->mode) {
		case Mode::WINS:
			mode = "WINS(UDP/137)";
			break;
		case Mode::MDNS:
			mode = "MDNS(UDP/5353)";
			break;
		case Mode::LLMNR:
			mode = "LLMNR(UDP/5355)";
			break;
		}
		printf("%s mode\n\n", mode);
	}

	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET) {
		throw STRERROR("socket: ");
	}

	int yes = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(port());
	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
		throw STRERROR("bind: ");
	}

	if (isMDNS() || isLLMNR()) {
		char const *addr = "224.0.0.251";
		if (isLLMNR()) {
			addr = "224.0.0.252";
		}
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_interface.s_addr = INADDR_ANY;
		mreq.imr_multiaddr.s_addr = inet_addr(addr);
		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) != 0) {
			throw STRERROR("setsockopt : ");
		}
	}

	char buf[2000];

	while (1) {
		cleanup();
		socklen_t salen = sizeof(sa);
		int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &salen);
		if (len < 12 || len > (int)sizeof(buf)) {
			continue;
		}

		if (get_hosts_time() != pv->hoststime) {
			read_hosts_file();
		}

		std::vector<char> res;
		dns_header_t header;
		std::list<question_t> questions;
		std::list<answer_t> answers;
		parse_response(buf, buf + len, &header, &questions, &answers);

		if ((header.flags & 0xf800) == 0x0000) { // standard query
			for (std::list<question_t>::const_iterator it = questions.begin(); it != questions.end(); it++) {
				question_t const &q = *it;
				if (q.clas == DNS_CLASS_IN) {
					if (q.type == DNS_TYPE_PTR) {
						// ignore
					} else {
						std::string name;
						switch (pv->mode) {
						case Mode::WINS:
							if (q.type == DNS_TYPE_NB) {
								int rt = -1;
								name = decode_netbios_name(q.name, &rt);
								if (rt != 0) {
									continue;
								}
							}
							break;
						case Mode::MDNS: // fallthru
						case Mode::LLMNR: // fallthru
						default:
							if (q.type == DNS_TYPE_A) {
								name = q.name;
							}
							break;
						}
						if (!name.empty()) {
							if (verbose()) {
								uint32_t from = ntohl(sa.sin_addr.s_addr);
								printf("query: \"%s\" by %s\n", name.c_str(), stripv4(from).c_str());
							}
							dns_a_record_t record;
							bool found = false;
							{
								auto it = pv->dns_a_map.map.find(name);
								if (it != pv->dns_a_map.map.end()) { // found
									record = it->second;
									found = true;
								} else if (is_self_mode()) {
									if (isDNS()) {
										hostent *h = gethostbyname(name.c_str());
										if (h) {
											record.addr = *(uint32_t *)h->h_addr;
											found = true;
										}
									} else if (eqi(name, pv->my_host_name) || eqi(name, pv->my_host_name_local)) {
										uint32_t src = ntohl(((struct sockaddr_in *)&sa)->sin_addr.s_addr);
										if (get_my_address(src, &record)) {
											found = true;
										}
									}
								}
							}
							if (found) {
								res.reserve(1000);
								make_response(header, q, record, &res);
								if (verbose()) {
									printf("reply: %s\n", stripv4(record.addr).c_str());
								}
								goto L1;
							} else { // not found
								if (isDNS() && q.type == DNS_TYPE_A) {
									uint32_t server = get_upstream_server();
									if (server != 0) {
										uint16_t id = pv->next_transaction_id++;
										delete_pending_query(id);
										{
											query_t t;
											t.time = time(0);
											t.requester_id = header.id;
											t.upstream_id = id;
											t.type = q.type;
											t.peer = sa;
											t.name = q.name;
											push_query(t);
										}
										std::vector<char> req;
										req.reserve(1000);
										record.addr = 0;
										write_dns_header(&req, id, 0x0100, 1, 0, 0, 0);
										write_dns_answer_rr(&req, q.name, DNS_TYPE_A, DNS_CLASS_IN, 0, record);
										struct sockaddr_in to = sa;
										to.sin_family = AF_INET;
										to.sin_addr.s_addr = htonl(server);
										to.sin_port = htons(port());
										sendto(sock, &req[0], (int)req.size(), 0, (struct sockaddr *)&to, sizeof(sockaddr_in)); // relay
										if (verbose()) {
											printf("relay: %s\n", stripv4(server).c_str());
										}
										goto L2;
									}
									if (verbose()) {
										printf("unknown: %s\n", name.c_str());
									}
								} else {
									goto L2;
								}
							}
						} else if (q.type == DNS_TYPE_AAAA) {
							// ignore
						}
					}
				}
			}
L1:;
			if (res.empty()) {
				if (isDNS()) {
					res.resize(12);
					dns_header_t *h = (dns_header_t *)&res[0];
					h->id = htons(header.id);
					h->flags = htons(0x8003); // no such name
				}
			}
			sendto(sock, &res[0], (int)res.size(), 0, (struct sockaddr *)&sa, sizeof(sockaddr_in));
L2:;
		} else if ((header.flags & 0xf80f) == 0x8000) { // response
			uint16_t id = header.id;
			query_t q;
			if (take_query(id, &q)) {
				if (q.type == DNS_TYPE_A) {
					if (questions.size() == 1 && questions.front().name == q.name) {
						std::vector<uint32_t> addrs;
						addrs.reserve(10);
						for (std::list<answer_t>::const_iterator it = answers.begin(); it != answers.end(); it++) {
							answer_t const &a = *it;
							if (a.type == DNS_TYPE_A && a.clas == DNS_CLASS_IN && a.data.size() == 4) {
								uint32_t addr = ntohl(*(uint32_t *)&a.data[0]);
								addrs.push_back(addr);
							}
						}
						if (addrs.size() > 0) {
							res.reserve(1000);
							write_dns_header(&res, q.requester_id, 0x8180, 0, (uint16_t)addrs.size(), 0, 0);
							for (int i = 0; i < (int)addrs.size(); i++) {
								dns_a_record_t item;
								item.addr = addrs[i];
								write_dns_answer_rr(&res, q.name, DNS_TYPE_A, DNS_CLASS_IN, ttl(), item);
							}
							sendto(sock, &res[0], (int)res.size(), 0, (struct sockaddr *)&q.peer, sizeof(sockaddr_in));
							if (verbose()) {
								for (int i = 0; i < (int)addrs.size(); i++) {
									printf("%s %s\n"
										, i == 0 ? "reply:" : "      "
										, stripv4(addrs[i]).c_str()
										);
								}
							}
						}
					}
				}
			}
		}
	}

	closesocket(sock);
}

