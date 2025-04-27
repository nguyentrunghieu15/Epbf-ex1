//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common/xdp-parse-helper.h"
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_endian.h>

#define RADIUS_PORT_L 1812
#define RADIUS_PORT_A 1813

struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 256);
} radius_events SEC(".maps");

struct radius_package
{
  __u8 code;
  __u8 identifier;
  __u16 length;
  __u8 authenticator[16];
  __u8 apvs[256];
};

SEC("xdp")
int radius_parser(struct xdp_md *ctx)
{
  char fmt3[] = "Hiro get a package";
  bpf_trace_printk(fmt3, sizeof(fmt3));
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth;
  struct udphdr *udph;
  /* These keep track of the next header type and iterator pointer */
  struct hdr_cursor nh;
  int nh_type;

  /* Start next header cursor position at data start */
  nh.pos = data;
  nh_type = parse_ethhdr(&nh, data_end, &eth);
  if (nh_type == bpf_htons(ETH_P_IPV6))
  {
    struct ipv6hdr *ih6;
    nh_type = parse_ip6hdr(&nh, data_end, &ih6);
    if (nh_type == bpf_htons(IPPROTO_UDP))
    {
      goto udp;
    }
  }
  else if (nh_type == bpf_htons(ETH_P_IP))
  {
    struct iphdr *iph;
    nh_type = parse_iphdr(&nh, data_end, &iph);
    if (nh_type == bpf_htons(IPPROTO_UDP))
    {
      goto udp;
    }
  }
  return XDP_PASS;
udp:
  nh_type = parse_udphdr(&nh, data_end, &udph);
  if (nh_type == -1)
  {
    return XDP_PASS;
  }
  char fmt[] = "Hiro get a upd package";
  bpf_trace_printk(fmt, sizeof(fmt));
  if (udph->dest != bpf_htons(RADIUS_PORT_L) || udph->dest != bpf_htons(RADIUS_PORT_A))
  {
    return XDP_PASS;
  }
  char fmt1[] = "Hiro get a radius package";
  bpf_trace_printk(fmt1, sizeof(fmt1));
  struct radius_package *rpk;
  rpk = nh.pos;
  if (rpk + 1 > data_end)
  {
    return XDP_PASS;
  }
  nh.pos = rpk + 1;
  int len;
  len = bpf_ntohs(rpk->length) - sizeof(struct radius_package);
  if (len < 0)
  {
    return XDP_PASS;
  }
  struct radius_package rpkdest;
  bpf_probe_read_kernel(&rpkdest, sizeof(struct radius_package), rpk);
  bpf_perf_event_output(ctx, &radius_events, BPF_F_CURRENT_CPU, &rpkdest, sizeof(rpkdest));
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";