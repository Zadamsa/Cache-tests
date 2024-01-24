#include <Packet.h>
#include <IpAddress.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <PayloadLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <IPLayer.h>
#include <DnsLayer.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <string>
#include "cache.hpp"
#include <chrono>
#include <iostream>
#include <deque>
#include <mutex>
using namespace pcpp;

class PacketConverter{
protected:
    ipxp::Packet createPacket(pcpp::RawPacket& packet) {
        ipxp::Packet ipxp_pkt = {0};
        pcpp::Packet parsedPacket(&packet);

        if (pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<IPv4Layer>()){
            ipxp_pkt.ip_version = ipxp::IP::v4;
            ipxp_pkt.src_ip.v4 = pcpp::IPv4Address(ipLayer->getSrcIPAddress().toString()).toInt();
            ipxp_pkt.dst_ip.v4 = pcpp::IPv4Address(ipLayer->getDstIPAddress().toString()).toInt();
            ipxp_pkt.ip_proto = ipLayer->getIPv4Header()->protocol;
            //ipxp_pkt
        }else if (auto ipLayer = parsedPacket.getLayerOfType<IPv6Layer>()){
            ipxp_pkt.ip_version = ipxp::IP::v6;
            pcpp::IPv6Address(ipLayer->getSrcIPAddress().toString()).copyTo(ipxp_pkt.src_ip.v6);
            pcpp::IPv6Address(ipLayer->getDstIPAddress().toString()).copyTo(ipxp_pkt.dst_ip.v6);
            ipxp_pkt.ip_proto = ipLayer->getIPv6Header()->nextHeader;
        }else return;
        ipxp_pkt.vlan_id = 0;

        ipxp_pkt.src_port = ipxp_pkt.dst_port = 0;
        if (auto tcpLayer = parsedPacket.getLayerOfType<TcpLayer>()){
            ipxp_pkt.src_port = tcpLayer->getTcpHeader()->portSrc;
            ipxp_pkt.dst_port = tcpLayer->getTcpHeader()->portDst;
        } else if (auto udpLayer = parsedPacket.getLayerOfType<UdpLayer>()){
            ipxp_pkt.src_port = udpLayer->getUdpHeader()->portSrc;
            ipxp_pkt.dst_port = udpLayer->getUdpHeader()->portDst;
        }
        return ipxp_pkt;
    }
};


class Analyzer: public PacketConverter{
public:
    ipxp::NHTFlowCache<true> m_cache;


    Analyzer(): m_cache(){
        //m_cache = ipxp::NHTFlowCache<true>();
        m_cache.init(nullptr);
    }

    void start(std::string filename) noexcept{
        PcapFileReaderDevice sniffer(filename);
        if (!sniffer.open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return;
        }
        pcpp::RawPacket packet;
        while(sniffer.getNextPacket(packet)){
            m_cache.put_pkt(createPacket(packet));
        }
    }


};

class GASearcher : public PacketConverter{
    std::deque<std::pair<ipxp::Packet,uint8_t>> m_queue;
    std::mutex m_queue_mutex;
    std::array<uint32_t,4> m_results;
    std::atomic<bool> m_exit = false;
    std::condition_variable m_cond;
    uint8_t m_thread_count = 4;
    std::vector<std::thread> m_threads;

    void start(std::string filename) noexcept{
        PcapFileReaderDevice sniffer(filename);
        if (!sniffer.open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return;
        }

        std::thread packet_reader([this](){ convertPackets();});
        for(int i = 0; i < m_thread_count; i++)
            m_threads
    }
    void convertPackets(){

        pcpp::RawPacket packet;
        while(!m_exit){
            std::unique_lock ul(m_queue_mutex);
            m_cond.wait(ul, [this,thread_count](){return m_queue.back().second == m_thread_count;});
            while(m_queue.front().second == m_thread_count)
                m_queue.pop_front();
            while(sniffer.getNextPacket(packet) && m_queue.size() < 10000)
                m_queue.emplace_back(createPacket(packet),0);

            if (m_queue.size() >= 10000)
                m_exit = true;
            ul.unlock();
        }
    }
    void mutateConfiguration(const GAConfiguration& original_configuration, uint8_t thread_number){
        GAConfiguration configuration = original_configuration.mutate();
        while(configuration == original_configuration)
            configuration = original_configuration.mutate();
        ipxp::NHTFlowCache<true> cache(configuration);
        while(!m_exit){
            std::unique_lock ul(m_queue_mutex);
            ul.unlock();
            for(auto& val: m_queue){
                m_cache.put_pkt(val.first);
                val.second++;
            }
            m_cond.notify_one();
        }
        m_results[thread_number] = cache.m_not_empty;
    }
};


int main(int argc, char** argv){
    Analyzer a;
    if (argc < 2)
        return -1;
    auto start = std::chrono::high_resolution_clock::now();
    a.start(argv[1]);
    std::cout << "Total time = " <<
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count() << " us" << std::endl;
    return 0;
}