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

struct radiushdr
{
  __u8 code;
  __u8 identifier;
  __u16 length;
  __u8 authenticator[16];
};

SEC("xdp")
int radius_parser(struct xdp_md *ctx)
{
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
    if (nh_type == IPPROTO_UDP)
    {
      goto udp;
    }
  }
  else if (nh_type == bpf_htons(ETH_P_IP))
  {
    struct iphdr *iph;
    nh_type = parse_iphdr(&nh, data_end, &iph);
    if (nh_type == IPPROTO_UDP)
    {
      goto udp;
    }
  }
  return XDP_PASS;
udp:
  nh_type = parse_udphdr(&nh, data_end, &udph);
  if (nh_type < 0)
  {
    return XDP_PASS;
  }
  if (bpf_ntohs(udph->dest) != RADIUS_PORT_L && bpf_ntohs(udph->dest) != RADIUS_PORT_A)
  {
    return XDP_PASS;
  }
  struct radiushdr *radiush;
  radiush = nh.pos;
  if (radiush + 1 > data_end)
  {
    return XDP_PASS;
  }
  nh.pos = radiush + 1;
  __u16 len = bpf_ntohs(radiush->length) - sizeof(struct radiushdr);
  struct radius_package rpkdest;
  memset(&rpkdest, 0, sizeof(rpkdest));
  if (len < 0)
  {
    return XDP_PASS;
  }
  bpf_probe_read_kernel(&rpkdest, sizeof(struct radiushdr), radiush);
  __u8 *attributies = nh.pos;
  if (attributies + len > data_end)
  {
    return XDP_PASS;
  }
  bpf_probe_read_kernel(rpkdest.apvs, sizeof(__u8) * 256, attributies);
  bpf_perf_event_output(ctx, &radius_events, BPF_F_CURRENT_CPU, &rpkdest, sizeof(rpkdest));
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";