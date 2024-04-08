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

static __always_inline void swap_port(struct udphdr *udp)
{
    /* __be32 tmp = udp->source; */
    udp->source = udp->dest;
    /* equivalent to bpf_htons(22222) */ 
    udp->dest = 52822;
}

    __attribute__((__always_inline__))
static inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

__attribute__((__always_inline__))
static inline void ipv4_csum(void* data_start, int data_size, __u64* csum) {
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void ipv4_l4_csum(void* data_start, __u32 data_size,
    __u64* csum, struct iphdr* iph, __u16 len, void *data_end) {
    __u32 tmp = 0;
    *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
    *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
    tmp = __builtin_bswap32((__u32)(iph->protocol));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    tmp = __builtin_bswap32((__u32)len);
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    /* *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum); */
    *csum = csum_fold_helper(*csum);
}

SEC("monitoring")
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
    swap_port(udp);

    __u32 csum = 0;
    // IP のチェックサムが0となってしまう．いれてはいけない．
    /* ip->check = 0; */
    /* ipv4_csum(ip, sizeof(struct iphdr), &csum); */
    /* ip->check = csum; */

    csum = 0;
    udp->check = 0;

    /* csum += ~bpf_icmp_checksum((__u16 *)&ip->saddr, sizeof(ip->saddr)); */
    /* csum += ~bpf_icmp_checksum((__u16 *)&ip->daddr, sizeof(ip->daddr)); */
    /* csum += ~bpf_icmp_checksum((__u16 *)&ip->protocol, sizeof(ip->protocol)); */
    /* csum += ~bpf_icmp_checksum((__u16 *)&udp->len, sizeof(udp->len)); */
    /* int len = (int)((__u64)data_end - (__u64)udp); */
    /* csum += ~bpf_icmp_checksum((__u16 *)&udp, len); */
    /* csum = (csum & 0xffff) + (csum >> 16); */
    
    /* udp->check = (__u16)~csum; */

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
