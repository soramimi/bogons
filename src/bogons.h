#ifndef BOGONS_H
#define BOGONS_H

#include <stdint.h>
#include <string>
#include <vector>
#include <list>
#include <map>

class bogons {
public:
	enum class Mode {
		DNS,
		MDNS,
		WINS,
		LLMNR,
	};
private:
	struct dns_a_record_t;
	struct dns_header_t;
	struct query_t;
	struct question_t;
	struct answer_t;
	struct name_map_t;

	struct Private;
	Private *m;

public:
	bogons(std::string const &inifile, std::string const &hostsfile);
	~bogons();
	void set_verbose(bool f);
	void set_mode(Mode mode);
	void main();
	bool is_self_mode() const;
	void set_self_mode(bool f);
	void update_names();
private:
	static inline bool eqi(std::string const &l, std::string const &r);
	bool verbose() const;
	bool isDNS() const;
	bool isMDNS() const;
	bool isWINS() const;
	bool isLLMNR() const;
	uint16_t port() const;
	int ttl() const;
	static void write(std::vector<char> *out, char c);
	static void write(std::vector<char> *out, char const *src, int len);
	static void write_us(std::vector<char> *out, uint16_t v);
	static void write_ul(std::vector<char> *out, uint32_t v);
	void write_name(std::vector<char> *out, std::string const &name);
	int decode_name(char const *begin, char const *end, char const *ptr, std::vector<char> *out);
	int decode_name(char const *begin, char const *end, char const *ptr, std::string *name);
	static void split(char const *begin, char const *end, std::vector<std::string> *out);
	static std::string trimmed(char const *left, char const *right);
	static void parse_ini_file(char const *path, std::map<std::string, std::string> *out);
	static void parse_hosts_file(char const *path, name_map_t *out);
	time_t get_hosts_time();
	void read_hosts_file();
	static void write_dns_header(std::vector<char> *out, uint16_t id, uint16_t flags, uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount);
	void write_dns_question_rr(std::vector<char> *out, std::string const &name, uint16_t type, uint16_t clas);
	void write_dns_answer_rr(std::vector<char> *out, std::string const &name, uint16_t type, uint16_t clas, uint32_t ttl, dns_a_record_t const &item);
	void write_wins_rr(std::vector<char> *out, std::string const &name, uint16_t type, uint16_t clas, uint32_t ttl, uint16_t nameflags, dns_a_record_t const &item);
	int parse_question_section(char const *begin, char const *end, char const *ptr, question_t *out);
	bool get_ini_string(std::string const &name, std::string *out) const;
	std::string get_ini_string(std::string const &name, std::string const &def = std::string()) const;
	uint32_t get_upstream_server();
	static uint32_t get_addr_by_name(char const *name);
	void init_upstream_server();
	void cleanup();
	bool take_query(uint16_t id, query_t *out);
	void delete_pending_query(uint16_t id);
	void push_query(query_t const &query);
	std::string decode_netbios_name(std::string const &name, int *restype);
	bool get_my_address(uint32_t srcaddr, dns_a_record_t *out);
	void make_response(dns_header_t const &header, question_t const &q, dns_a_record_t const &r, std::vector<char> *out);
	void init_ttl();
	std::string stripv4(uint32_t a);
	void parse_response(char const *begin, char const *end, dns_header_t *header, std::list<question_t> *questions, std::list<answer_t> *answers);
	void update_netif_table();
};

#endif // BOGONS_H
