/**
 * \file cache.hpp
 * \brief "NewHashTable" flow cache
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *
 *
 */
#ifndef IPXP_STORAGE_CACHE_HPP
#define IPXP_STORAGE_CACHE_HPP

#include <memory>
#include <optional>
#include <string>

#include <array>
#include "Packet.h"
/*#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/utils.hpp>*/

namespace ipxp {

template<uint16_t IPSize>
struct __attribute__((packed)) flow_key {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t ip_version;
    std::array<uint8_t, IPSize> src_ip;
    std::array<uint8_t, IPSize> dst_ip;
    uint16_t vlan_id;
    flow_key<IPSize>& operator=(const Packet& pkt) noexcept;
    flow_key<IPSize>& save_reversed(const Packet& pkt) noexcept;
};
struct __attribute__((packed)) flow_key_v4 : public flow_key<4> {
    flow_key_v4& operator=(const Packet& pkt) noexcept;
    flow_key_v4& save_reversed(const Packet& pkt) noexcept;
    flow_key_v4& save_sorted(const Packet& pkt) noexcept;
};
struct __attribute__((packed)) flow_key_v6 : public flow_key<16> {
    flow_key_v6& operator=(const Packet& pkt) noexcept;
    flow_key_v6& save_reversed(const Packet& pkt) noexcept;
    flow_key_v6& save_sorted(const Packet& pkt) noexcept;
};

static const uint32_t DEFAULT_FLOW_CACHE_SIZE = 17; // 131072 records total

static const uint32_t DEFAULT_FLOW_LINE_SIZE = 4; // 16 records per line


class FlowRecord {
    uint64_t m_hash;

public:
    Flow m_flow;

    FlowRecord();
    ~FlowRecord();

    void erase();
    void reuse();

    inline bool is_empty() const;
    inline bool belongs(uint64_t pkt_hash) const;
    void create(const Packet& pkt, uint64_t pkt_hash);
    void update(const Packet& pkt, bool src);
};

template<bool NEED_FLOW_CACHE_STATS = false>
class NHTFlowCache  {
public:
    NHTFlowCache();
    virtual ~NHTFlowCache() ;
    virtual void init(const char* params) ;
    void close() ;
    //void set_queue(ipx_ring_t* queue) override;
    //OptionsParser* get_parser() const override { return new CacheOptParser(); }
    //std::string get_name() const override { return "cache"; }

    virtual int put_pkt(Packet& pkt) ;
    void export_expired(time_t ts) ;

protected:
    uint32_t m_cache_size;
    uint32_t m_line_size;
    uint32_t m_line_mask;
    uint32_t m_line_new_idx;
    uint32_t m_qsize;
    uint32_t m_qidx;
    uint32_t m_timeout_idx;
    uint32_t m_active;
    uint32_t m_inactive;
    bool m_split_biflow;
    uint8_t m_keylen;
    char m_key[100];
    char m_key_inv[100];
    std::unique_ptr<FlowRecord*[]> m_flow_table;
    std::unique_ptr<FlowRecord[]> m_flow_records;

    virtual void flush(Packet& pkt, size_t flow_index, int ret, bool source_flow);
    virtual bool create_hash_key(const Packet& pkt) noexcept;
    void export_flow(size_t index);
    static uint8_t get_export_reason(Flow& flow);
    void finish();
    //void get_opts_from_parser(const CacheOptParser& parser);

    std::pair<bool, uint32_t>
    find_existing_record(uint32_t begin_line, uint32_t end_line, uint64_t hashval) const noexcept;
    virtual uint32_t
    enhance_existing_flow_record(uint32_t flow_index, uint32_t line_index) noexcept;
    std::pair<bool, uint32_t>
    find_empty_place(uint32_t begin_line, uint32_t end_line) const noexcept;
    virtual uint32_t put_into_free_place(
        uint32_t flow_index,
        bool empty_place_found,
        uint32_t begin_line,
        uint32_t end_line) noexcept;

    bool process_last_tcp_packet(Packet& pkt, uint32_t flow_index) noexcept;
    virtual bool create_new_flow(uint32_t flow_index, Packet& pkt, uint64_t hashval) noexcept;
    virtual bool flush_and_update_flow(uint32_t flow_index, Packet& pkt) noexcept;
    virtual void prepare_and_export(uint32_t flow_index) noexcept;
    virtual void prepare_and_export(uint32_t flow_index, uint32_t reason) noexcept;

    static void test_attributes();
    uint32_t toeplitzHash(const Packet& pkt) const noexcept;
    uint32_t my_hash(Packet& pkt) const noexcept;

};
template<>
class NHTFlowCache<true> : public NHTFlowCache<false> {
public:
    NHTFlowCache();
    ~NHTFlowCache() override;
    uint64_t m_empty;
    uint64_t m_not_empty;
    uint64_t m_hits;
    uint64_t m_expired;
    uint64_t m_flushed;
    uint64_t m_lookups;
    uint64_t m_lookups2;
    uint64_t m_put_time;
    uint64_t m_sort_time;
    uint64_t m_copy_time;
    void init(const char* params) override;

    int put_pkt(Packet& pkt) override;

    uint32_t
    enhance_existing_flow_record(uint32_t flow_index, uint32_t line_index) noexcept override;
    uint32_t put_into_free_place(
        uint32_t flow_index,
        bool empty_place_found,
        uint32_t begin_line,
        uint32_t end_line) noexcept override;
    bool create_new_flow(uint32_t flow_index, Packet& pkt, uint64_t hashval) noexcept override;
    void flush(Packet& pkt, size_t flow_index, int ret, bool source_flow) override;
    void prepare_and_export(uint32_t flow_index) noexcept override;
    void prepare_and_export(uint32_t flow_index, uint32_t reason) noexcept override;
    void print_report() const noexcept;
    bool create_hash_key(const Packet& pkt) noexcept override;

};

} // namespace ipxp
#endif /* IPXP_STORAGE_CACHE_HPP */
