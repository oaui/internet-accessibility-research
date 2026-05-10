#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "logger.h"

/* HTTP payload that triggers censorship middleboxes */
#define DEFAULT_HTTP_PAYLOAD "GET / HTTP/1.1\r\nHost: onlyfans.com\r\n\r\n"
#define MAX_TCP_PSHACK_PAYLOAD_LEN 1400

static uint8_t *tcp_pshack_payload = NULL;
static size_t tcp_pshack_payload_len = 0;

static uint16_t num_source_ports;

static int pshack_global_initialize(struct state_conf *state)
{
	const char *usage_error =
	    "unknown probe specification (expected file:/path or text:STRING or hex:01020304)";
	num_source_ports = state->source_port_last - state->source_port_first + 1;
	tcp_pshack_payload = (uint8_t *)strdup(DEFAULT_HTTP_PAYLOAD);
	tcp_pshack_payload_len = strlen(DEFAULT_HTTP_PAYLOAD);
	if (!tcp_pshack_payload) {
		log_fatal("tcp_pshack", "unable to allocate default payload");
	}

	if (state->probe_args && strlen(state->probe_args) > 0) {
		char *args = strdup(state->probe_args);
		assert(args);
		char *c = strchr(args, ':');
		if (!c) {
			free(args);
			log_fatal("tcp_pshack", "%s", usage_error);
		}
		*c++ = '\0';

		if (strcmp(args, "text") == 0) {
			free(tcp_pshack_payload);
			tcp_pshack_payload = (uint8_t *)strdup(c);
			tcp_pshack_payload_len = strlen(c);
			if (!tcp_pshack_payload) {
				free(args);
				log_fatal("tcp_pshack", "unable to allocate text payload");
			}
		} else if (strcmp(args, "file") == 0) {
			FILE *inp = fopen(c, "rb");
			if (!inp) {
				free(args);
				log_fatal("tcp_pshack", "could not open payload file '%s'", c);
			}
			free(tcp_pshack_payload);
			tcp_pshack_payload = xmalloc(MAX_TCP_PSHACK_PAYLOAD_LEN);
			tcp_pshack_payload_len =
			    fread(tcp_pshack_payload, 1, MAX_TCP_PSHACK_PAYLOAD_LEN, inp);
			fclose(inp);
		} else if (strcmp(args, "hex") == 0) {
			if ((strlen(c) % 2) != 0) {
				free(args);
				log_fatal("tcp_pshack", "invalid hex input (length must be a multiple of 2)");
			}
			free(tcp_pshack_payload);
			tcp_pshack_payload_len = strlen(c) / 2;
			tcp_pshack_payload = xmalloc(tcp_pshack_payload_len);
			unsigned int n;
			for (size_t i = 0; i < tcp_pshack_payload_len; i++) {
				if (sscanf(c + (i * 2), "%2x", &n) != 1) {
					char nonhexchr = c[i * 2];
					free(args);
					log_fatal("tcp_pshack", "non-hex character: '%c'",
						  nonhexchr);
				}
				tcp_pshack_payload[i] = (n & 0xff);
			}
		} else {
			free(args);
			log_fatal("tcp_pshack", "%s", usage_error);
		}
		free(args);
	}

	return EXIT_SUCCESS;
}

static int pshack_thread_initialize(void **arg_ptr)
{
	(void)arg_ptr;
	return EXIT_SUCCESS;
}

static int pshack_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw,
				 UNUSED void *arg)
{
	struct ether_header *eth = (struct ether_header *)buf;
	make_eth_header(eth, src, gw);

	struct ip *ip = (struct ip *)(&eth[1]);
	uint16_t len = htons(20 + 20 + tcp_pshack_payload_len);
	make_ip_header(ip, IPPROTO_TCP, len);

	struct tcphdr *tcp = (struct tcphdr *)(&ip[1]);
	make_tcp_header(tcp, TH_PUSH | TH_ACK);

	/* Write static payload */
	char *payload = (char *)(&tcp[1]);
	memcpy(payload, tcp_pshack_payload, tcp_pshack_payload_len);

	return EXIT_SUCCESS;
}

static int pshack_make_packet(void *buf, size_t *buf_len,
			      ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
			      port_n_t dport, uint8_t ttl,
			      uint32_t *validation, int probe_num,
			      uint16_t ip_id, UNUSED void *arg)
{
	struct ether_header *eth = (struct ether_header *)buf;
	struct ip *ip = (struct ip *)(&eth[1]);
	struct tcphdr *tcp = (struct tcphdr *)(&ip[1]);

	ip->ip_src.s_addr = src_ip;
	ip->ip_dst.s_addr = dst_ip;
	ip->ip_ttl = ttl;
	ip->ip_id = ip_id;

	port_h_t sport = get_src_port(num_source_ports, probe_num, validation);
	tcp->th_sport = htons(sport);
	tcp->th_dport = dport;
	tcp->th_seq = htonl(validation[0]);
	/* Non-zero ack to look like mid-session */
	tcp->th_ack = htonl(validation[0] + 1);

	tcp->th_sum = 0;
	tcp->th_sum = tcp_checksum(20 + tcp_pshack_payload_len,
				   ip->ip_src.s_addr,
				   ip->ip_dst.s_addr, tcp);

	ip->ip_sum = 0;
	ip->ip_sum = zmap_ip_checksum((unsigned short *)ip);

	*buf_len = sizeof(struct ether_header) + sizeof(struct ip) +
		   sizeof(struct tcphdr) + tcp_pshack_payload_len;
	return EXIT_SUCCESS;
}

static void pshack_print_packet(FILE *fp, void *buf)
{
	struct ether_header *eth = (struct ether_header *)buf;
	struct ip *ip = (struct ip *)(&eth[1]);
	struct tcphdr *tcp = (struct tcphdr *)(&ip[1]);
	fprintf(fp, "tcp_pshack { sport: %u | dport: %u | seq: %u }\n",
		ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq));
	fprintf_ip_header(fp, ip);
	fprintf_eth_header(fp, eth);
	fprintf(fp, PRINT_PACKET_SEP);
}

static int pshack_validate_packet(const struct ip *ip_hdr, uint32_t len,
				  uint32_t *src_ip, uint32_t *validation,
				  const struct port_conf *ports)
{
	(void)ports;
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return PACKET_INVALID;
	}
	struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
	if (!tcp) {
		return PACKET_INVALID;
	}
	port_h_t dport = ntohs(tcp->th_dport);
	if (!check_dst_port(dport, num_source_ports, validation)) {
		return PACKET_INVALID;
	}
	if (!blocklist_is_allowed(*src_ip)) {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

static void pshack_process_packet(const u_char *packet, uint32_t len,
				  fieldset_t *fs, UNUSED uint32_t *validation,
				  UNUSED struct timespec ts)
{
	struct ip *ip_hdr = get_ip_header(packet, len);
	assert(ip_hdr);
	struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
	assert(tcp);

	int ip_len = ntohs(ip_hdr->ip_len);
	int ip_hlen = ip_hdr->ip_hl * 4;
	int tcp_hlen = tcp->th_off * 4;
	int data_len = ip_len - ip_hlen - tcp_hlen;
	if (data_len < 0)
		data_len = 0;

	fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
	fs_add_uint64(fs, "data_len", (uint64_t)data_len);

	if (tcp->th_flags & TH_RST) {
		fs_add_constchar(fs, "classification", "rst");
		fs_add_bool(fs, "success", 0);
	} else if (data_len > 128) {
		fs_add_constchar(fs, "classification", "middlebox");
		fs_add_bool(fs, "success", 1);
	} else {
		fs_add_constchar(fs, "classification", "data");
		fs_add_bool(fs, "success", 0);
	}
}

static int pshack_global_cleanup(UNUSED struct state_conf *zconf,
				 UNUSED struct state_send *zsend,
				 UNUSED struct state_recv *zrecv)
{
	if (tcp_pshack_payload) {
		free(tcp_pshack_payload);
		tcp_pshack_payload = NULL;
	}
	tcp_pshack_payload_len = 0;
	return EXIT_SUCCESS;
}

static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "source port"},
    {.name = "dport", .type = "int", .desc = "dest port"},
    {.name = "seqnum", .type = "int", .desc = "sequence number"},
    {.name = "acknum", .type = "int", .desc = "ack number"},
    {.name = "data_len", .type = "int", .desc = "response payload length"},
    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS,
};

probe_module_t module_tcp_pshack = {
    .name = "tcp_pshack",
    .max_packet_length = sizeof(struct ether_header) + sizeof(struct ip) +
			 sizeof(struct tcphdr) + MAX_TCP_PSHACK_PAYLOAD_LEN,
    .pcap_filter = "tcp",
    .pcap_snaplen = 1600,
    .port_args = 1,
    .global_initialize = &pshack_global_initialize,
    .thread_initialize = &pshack_thread_initialize,
    .prepare_packet = &pshack_prepare_packet,
    .make_packet = &pshack_make_packet,
    .print_packet = &pshack_print_packet,
    .validate_packet = &pshack_validate_packet,
    .process_packet = &pshack_process_packet,
    .close = &pshack_global_cleanup,
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0]),
    .helptext = "Sends TCP PSH+ACK with configurable payload. "
		"Use --probe-args=text:STRING, --probe-args=hex:01020304, "
		"or --probe-args=file:/path/to/payload.bin.",
};
