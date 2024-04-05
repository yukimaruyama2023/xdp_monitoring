#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h> // needed for "IPPROTO_UDP"
/* #include <sys/socket.h> */
 
#define ETH_ALEN 6
#define PORT_NUM 22222

static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
    __u8 h_tmp[ETH_ALEN];

    __builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ip(struct iphdr *ip)
{
    __be32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
}

/* static __always_inline void swap_src_dst_port(struct udphdr *udp) */
/* { */
/*     __be16 tmp = udp->source; */
/*     udp->source = udp->dest; */
/*     udp->dest = tmp; */
/* } */

SEC("udp_test")
int udp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end; 
    void *data = (void *)(long)ctx->data; 
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    long all_cpu_metrics[10] = {0,0,0,0,0,0,0,0,0,0};
    bpf_get_all_cpu_metrics(all_cpu_metrics);

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    /* if (eth->h_proto != ETH_P_IP) return XDP_PASS; */
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != htons(PORT_NUM)) return XDP_PASS;

    for (int i = 0; i < 10; i++) {
        if ((void *)payload + sizeof(long) > data_end) return XDP_PASS;
        *(long *)payload = (long)all_cpu_metrics[i];
        payload += sizeof(long);
    }

    swap_src_dst_mac(eth);
    swap_src_dst_ip(ip);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
