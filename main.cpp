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
using namespace pcpp;
class Analyzer{
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
            processPackets(packet);
        }

    }
    void processPackets(pcpp::RawPacket& packet){
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

        m_cache.put_pkt(ipxp_pkt);
        /*Flow flow;
        Packet parsedPacket(rawPacket);

        // Extracting the IP layer
        auto ipLayer = parsedPacket.getLayerOfType<IPv4Layer>();
        if (!ipLayer) {
            m_packet_count_not_ip++;
            return true;
        }

        m_packet_count_ip++;
        flow.src_ip = ipLayer->getSrcIPAddress();
        flow.dst_ip = ipLayer->getDstIPAddress();

        size_t packetSize = 0;
        ProtocolType transportType = UnknownProtocol;

        // Extracting the transport layer
        if (auto tcpLayer = parsedPacket.getLayerOfType<TcpLayer>()) {
            flow.src_port = tcpLayer->getSrcPort();
            flow.dst_port = tcpLayer->getDstPort();
            packetSize = tcpLayer->getDataLen();
            m_tcp_bytes += packetSize;
            transportType = TCP;
            m_flow_count_TCP++;
            m_tcp_packets++;
        } else if (auto udpLayer = parsedPacket.getLayerOfType<UdpLayer>()) {
            flow.src_port = udpLayer->getSrcPort();
            flow.dst_port = udpLayer->getDstPort();
            packetSize = udpLayer->getDataLen();
            m_udp_bytes += packetSize;
            transportType = UDP;
            m_flow_count_UDP++;
            m_udp_packets++;
        } else {
            flow.src_port = flow.dst_port = 0;
        }
        auto last_layer =  parsedPacket.getLastLayer();
        if (last_layer->getProtocol() == PacketTrailer || last_layer->getProtocol() == GenericPayload)
            last_layer = last_layer->getPrevLayer() == nullptr ? last_layer : last_layer->getPrevLayer();
        if (auto searchIt = m_flows.find(flow); searchIt != m_flows.end()) {
            if (searchIt->first.src_ip == flow.src_ip && searchIt->first.src_port == flow.src_port) {
                searchIt->second.src_packets++;
                searchIt->second.src_bytes += packetSize;
            } else {
                searchIt->second.dst_packets++;
                searchIt->second.dst_bytes += packetSize;
            }
            if (last_layer->getOsiModelLayer() > searchIt->second.osi_layer &&
                ( last_layer->getOsiModelLayer() != OsiModelLayerUnknown || searchIt->second.osi_layer == OsiModelLayerUnknown )) {
                searchIt->second.osi_layer = last_layer->getOsiModelLayer();
                searchIt->second.last_type = last_layer->getProtocol();
            }
        } else {
            if (packetSize == 0)
                packetSize = parsedPacket.getRawPacketReadOnly()->getRawDataLen();
            FlowData fd(1, 0, packetSize, 0);
            fd.last_type = last_layer->getProtocol();
            fd.transport_type = transportType;
            m_flows.emplace(flow,fd);
        }
        auto tcp_layer = parsedPacket.getLayerOfType<TcpLayer>();
        if (!tcp_layer || !m_export_rows)
            return true;
        auto ipv4_layer = parsedPacket.getLayerOfType<IPv4Layer>();
        auto ipv6_layer = parsedPacket.getLayerOfType<IPv6Layer>();
        auto tcp_header = tcp_layer->getTcpHeader();
        export_row(m_flows.find(flow)->second);
        if (ipv4_layer) {
            auto ip_header = ipv4_layer->getIPv4Header();
            m_flows.find(flow)->second.last_tcp_data = FlowData::LastTCPData(ip_header->totalLength,extractFlags(*tcp_header),ntohs(tcp_header->windowSize),ip_header->protocol);
        }else {
            auto ip_header = ipv6_layer->getIPv6Header();
            m_flows.find(flow)->second.last_tcp_data = FlowData::LastTCPData(ip_header->payloadLength,extractFlags(*tcp_header),ntohs(tcp_header->windowSize),ip_header->nextHeader);
        }
        m_flows.find(flow)->second.last_access = m_packet_count;
        return true;*/
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