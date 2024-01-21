//
// Created by zaida on 20.01.2024.
//

#ifndef TEST_CACHE_PACKET_H
#define TEST_CACHE_PACKET_H

#define IPPROTO_TCP 0
#define IPPROTO_UDP 1
#define IPPROTO_ICMP 2
#define IPPROTO_ICMPV6 3

#define FLOW_END_INACTIVE 0x01
#define FLOW_END_ACTIVE   0x02
#define FLOW_END_EOF      0x03
#define FLOW_END_FORCED   0x04
#define FLOW_END_NO_RES   0x05
union ipaddr_t {
    uint8_t  v6[16];  /**< IPv6 address. */
    uint32_t v4;      /**< IPv4 address  */
} ;
namespace ipxp {
    enum IP : uint8_t {
        v4 = 4,
        v6 = 6
    };
    struct Packet {
        struct timeval ts;

        uint8_t     dst_mac[6];
        uint8_t     src_mac[6];
        uint16_t    ethertype;

        uint16_t    ip_len; /**< Length of IP header + its payload */
        uint16_t    ip_payload_len; /**< Length of IP payload */
        uint8_t     ip_version;
        uint8_t     ip_ttl;
        uint8_t     ip_proto;
        uint8_t     ip_tos;
        uint8_t     ip_flags;
        ipaddr_t    src_ip;
        ipaddr_t    dst_ip;
        uint32_t    vlan_id;

        uint16_t    src_port;
        uint16_t    dst_port;
        uint8_t     tcp_flags;
        uint16_t    tcp_window;
        uint64_t    tcp_options;
        uint32_t    tcp_mss;
        uint32_t    tcp_seq;
        uint32_t    tcp_ack;
        bool        source_pkt; /**< Direction of packet from flow point of view */
    };
};
struct Flow {
    uint64_t flow_hash;

    struct timeval time_first;
    struct timeval time_last;
    uint64_t src_bytes;
    uint64_t dst_bytes;
    uint32_t src_packets;
    uint32_t dst_packets;
    uint8_t  src_tcp_flags;
    uint8_t  dst_tcp_flags;

    uint8_t  ip_version;

    uint8_t  ip_proto;
    uint16_t src_port;
    uint16_t dst_port;
    ipaddr_t src_ip;
    ipaddr_t dst_ip;

    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint8_t end_reason;
};

/**
 * \brief Tell storage plugin to flush (immediately export) current flow.
 * Behavior when called from post_create, pre_update and post_update: flush current Flow and erase FlowRecord.
 */
#define FLOW_FLUSH                  0x1

/**
 * \brief Tell storage plugin to flush (immediately export) current flow.
 * Behavior when called from post_create: flush current Flow and erase FlowRecord.
 * Behavior when called from pre_update and post_update: flush current Flow, erase FlowRecord and call post_create on packet.
 */
#define FLOW_FLUSH_WITH_REINSERT    0x3
#endif //TEST_CACHE_PACKET_H
