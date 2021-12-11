/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

void SimpleRouter::handleArp(const Buffer& packet, const std::string& inIface) {
  std::cout << "Handling ARP packet..." << std::endl;

  /* 检查ARP包合法性 */
  // 大小
  if (packet.size() != sizeof(arp_hdr) + sizeof(ethernet_hdr)) {
    std::cout << "Arp header is truncated, ignoring" << std::endl;
    return;
  }
  // 硬件类型
  arp_hdr* arp_ptr = (arp_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  if (ntohs(arp_ptr->arp_hrd) != arp_hrd_ethernet) {
    std::cout << "Arp hardware type is not ethernet, ignoring" << std::endl;
    return;
  }
  // 硬件地址
  if (arp_ptr->arp_hln != 0x06) {
    std::cout << "Arp hardware address length is invalid, ignoring" << std::endl;
    return;
  }
  // 协议类型
  if (ntohs(arp_ptr->arp_pro) != ethertype_ip) {
    std::cout << "Arp protocol type is not IPv4, ignoring" << std::endl;
    return;
  }
  // 协议地址
  if (arp_ptr->arp_pln != 0x04) {
    std::cout << "Arp protocol address length is invalid, ignoring" << std::endl;
    return;
  }
  // 操作符
  if (ntohs(arp_ptr->arp_op) != 1 && ntohs(arp_ptr->arp_op) != 2) {
    std::cout << "Arp opcode is invalid, ignoring" << std::endl;
    return;
  }

  /* 分request和reply处理 */
  const Interface* iface = findIfaceByName(inIface);
  // arp request
  if (ntohs(arp_ptr->arp_op) == 1) {
    if (arp_ptr->arp_tip == iface->ip) {
      handleArpRequest(packet, inIface);
    }
    else {
      std::cout << "Arp destination is not the router, ignoring" << std::endl;
    }
  }
  // arp reply
  else {
    handleArpReply(packet);
  }
}

void SimpleRouter::handleArpRequest(const Buffer& packet, const std::string& inIface) {
  std::cout << "Handling ARP request..." << std::endl;

  /* ARP request */
  ethernet_hdr* req_eth = (ethernet_hdr*)(packet.data());
  arp_hdr* req_arp = (arp_hdr*)((u_int8_t*)req_eth + sizeof(ethernet_hdr));

  /* ARP reply */
  Buffer* reply = new Buffer(packet);
  ethernet_hdr* rep_eth = (ethernet_hdr*)(reply->data());
  arp_hdr* rep_arp = (arp_hdr*)((uint8_t*)rep_eth + sizeof(ethernet_hdr));

  /* 修改参数 */
  // ethernet
  const Interface* iface = findIfaceByName(inIface);
  memcpy(rep_eth->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
  memcpy(rep_eth->ether_dhost, req_eth->ether_shost, ETHER_ADDR_LEN);

  // arp
  rep_arp->arp_sip = req_arp->arp_tip;
  rep_arp->arp_tip = req_arp->arp_sip;
  rep_arp->arp_op = htons(0x0002);
  memcpy(rep_arp->arp_sha, iface->addr.data(), 6);
  memcpy(rep_arp->arp_tha, req_arp->arp_sha, 6);

  /* 发送reply */
  sendPacket(*reply, inIface);
}

void SimpleRouter::handleArpReply(const Buffer& packet) {
  std::cout << "Handling ARP reply..." << std::endl;
  
  arp_hdr* arp_ptr = (arp_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  uint32_t sender_ip = arp_ptr->arp_sip;
  Buffer sender_mac(arp_ptr->arp_sha, arp_ptr->arp_sha + 6);

  /* 处理IP/MAC对 */
  // 插入新的IP/MAC对，并处理相应的包
  if (m_arp.lookup(sender_ip) == nullptr) {
    auto arp_req = m_arp.insertArpEntry(sender_mac, sender_ip);
    if (arp_req == nullptr) {
      std::cout << "No queued requests for the IP/MAC" << std::endl;
    }
    else {
      // 处理目的地址为对应IP/MAC对的包
      std::cout << "Handle queued requests for the IP/MAC" << std::endl;
      for (const auto& packet : arp_req->packets) {
        handlePacket(packet.packet, packet.iface);
      }
      m_arp.removeRequest(arp_req);
    }
  }
  // 否则跳过
  else {
    std::cout << "IP/MAC already exists" << std::endl;
  }
}

void SimpleRouter::handleICMPt3(const Buffer& packet) {
  ethernet_hdr* eth_ptr = (ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));

  /* 查找路由表和ARP cache */
  RoutingTableEntry routing_entry = m_routingTable.lookup(ip_ptr->ip_src);
  auto arp_entry = m_arp.lookup(ip_ptr->ip_src);

  /* 发送reply */
  Buffer* reply = new Buffer(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  const Interface* outIface = findIfaceByName(routing_entry.ifName);

  // 处理以太帧
  ethernet_hdr* rep_eth = (ethernet_hdr*)((uint8_t*)reply->data());
  memcpy(rep_eth, eth_ptr, sizeof(ethernet_hdr));
  memcpy(rep_eth->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
  memcpy(rep_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);

  // 处理IP
  ip_hdr* rep_ip = (ip_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr));
  memcpy(rep_ip, ip_ptr, sizeof(ip_hdr));
  rep_ip->ip_id = 0;
  rep_ip->ip_ttl = 64;
  rep_ip->ip_p = ip_protocol_icmp;
  rep_ip->ip_src = outIface->ip;
  rep_ip->ip_dst = ip_ptr->ip_src;
  rep_ip->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  rep_ip->ip_sum = 0;
  rep_ip->ip_sum = cksum(rep_ip, sizeof(ip_hdr));

  // 处理ICMP type3
  icmp_t3_hdr* rep_icmp_t3 = (icmp_t3_hdr*)((uint8_t*)reply->data() + sizeof(ip_hdr) + sizeof(ethernet_hdr));
  rep_icmp_t3->icmp_code = 1;
  rep_icmp_t3->icmp_type = 3;
  rep_icmp_t3->unused = 0;
  rep_icmp_t3->next_mtu = 0;
  rep_icmp_t3->icmp_sum = 0;
  memcpy((uint8_t*)(rep_icmp_t3->data), (uint8_t*)ip_ptr, ICMP_DATA_SIZE);
  rep_icmp_t3->icmp_sum = cksum(rep_icmp_t3, sizeof(icmp_t3_hdr));

  sendPacket(*reply, outIface->name);
}

void SimpleRouter::sendArpRequest(uint32_t ip) {
  Buffer* request = new Buffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));

  /* 查找路由表 */
  RoutingTableEntry routing_entry = m_routingTable.lookup(ip);
  const Interface* outIface = findIfaceByName(routing_entry.ifName);

  /* 发送request */
  // 处理以太帧
  ethernet_hdr* req_eth = (ethernet_hdr*)(request->data());
  req_eth->ether_type = htons(0x0806);
  memcpy(req_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  for (auto& i : req_eth->ether_dhost) {
    i = 0xff;
  }

  // 处理ARP
  arp_hdr* req_arp = (arp_hdr*)((uint8_t*)req_eth + sizeof(ethernet_hdr));
  req_arp->arp_op = htons(0x01);
  req_arp->arp_pro = htons(0x0800);
  req_arp->arp_sip = outIface->ip;
  req_arp->arp_tip = ip;
  req_arp->arp_hrd = htons(0x0001);
  req_arp->arp_hln = 0x06;
  req_arp->arp_pln = 0x04;
  memcpy(req_arp->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
  for (auto & i : req_arp->arp_tha){
      i = 0xff;
  }

  sendPacket(*request, outIface->name);
}

void SimpleRouter::handleIPv4(const Buffer& packet, const std::string& inIface) {
  std::cout << "Handling IPv4 packet..." << std::endl;
  
  /* 检查ip数据报合法性 */
  // 大小
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
    std::cout << "IPv4 header is truncated, ignoring" << std::endl;
    return;
  }
  // 校验和
  ip_hdr* ip_ptr = (ip_hdr*)((u_int8_t*)packet.data() + sizeof(ethernet_hdr));
  if (cksum(ip_ptr, sizeof(ip_hdr)) != 0xffff) {
    std::cout << "IPv4 checksum is incorrect, ignoring" << std::endl;
    return;
  }

  /* 判断目的地址 */
  // 指向本路由器
  if (findIfaceByIp(ip_ptr->ip_dst) != nullptr) {
    // ICMP
    if (ip_ptr->ip_p == ip_protocol_icmp) {
      handleICMP(packet, inIface);
    }
    // TCP & UDP
    else {
      handleICMPt3(packet, inIface, 1);
    }
  }
  // 指向其他地址，需要转发
  else {
    // 超时，无法转发
    if (ip_ptr->ip_ttl == 1) {
      handleICMPt3(packet, inIface, 2);
    }
    // 否则转发
    else {
      // 查找路由表
      RoutingTableEntry routing_entry = m_routingTable.lookup(ip_ptr->ip_dst);
      // 查找ARP cache
      auto arp_entry = m_arp.lookup(ip_ptr->ip_dst);
      // 如果没有对应的IP/MAC对，先将request加入队列
      if (arp_entry == nullptr) {
        m_arp.queueRequest(ip_ptr->ip_dst, packet, inIface);
      }
      // 否则转发
      else {
        handleForward(packet, inIface);
      }
    }
  }
}

void SimpleRouter::handleICMP(const Buffer& packet, const std::string& inIface) {
  std::cout << "Handling ICMP packet..." << std::endl;

  /* 检查ICMP报文合法性 */
  // 大小
  if (packet.size() < sizeof(icmp_hdr) + sizeof(ip_hdr) + sizeof(ethernet_hdr)) {
    std::cout << "ICMP header is truncated, ignoring" << std::endl;
    return;
  }
  // 类型
  icmp_hdr* icmp_ptr = (icmp_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  if (!(icmp_ptr->icmp_type == 8) || !(icmp_ptr->icmp_code == 0)) {
    std::cout << "ICMP type is invalid, ignoring" << std::endl;
    return;
  }
  // 校验和
  if (cksum((uint8_t*)icmp_ptr, packet.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr)) != 0xffff) {
    std::cout << "ICMP checksum is incorrect, ignoring" << std::endl;
    return;
  }

  ethernet_hdr* eth_ptr = (ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));

  /* 查找路由表和ARP cache */
  RoutingTableEntry routing_entry = m_routingTable.lookup(ip_ptr->ip_src);
  auto arp_entry = m_arp.lookup(ip_ptr->ip_src);
  // 如果没有IP/MAC对，将request加入队列
  if (arp_entry == nullptr) {
    m_arp.queueRequest(ip_ptr->ip_src, packet, inIface);
  }
  // 否则，发送echo reply
  else {
    const Interface* outIface = findIfaceByName(routing_entry.ifName);
    Buffer* reply = new Buffer(packet);

    // 修改以太帧
    ethernet_hdr* rep_eth = (ethernet_hdr*)((uint8_t*)reply->data());
    memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
    memcpy(rep_eth->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN);

    // 修改IPv4
    ip_hdr* rep_ip = (ip_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr));
    rep_ip->ip_id = 0;
    rep_ip->ip_ttl = 64;
    rep_ip->ip_dst = ip_ptr->ip_src;
    rep_ip->ip_src = ip_ptr->ip_dst;
    rep_ip->ip_sum = 0;
    rep_ip->ip_sum = cksum((uint8_t*)rep_ip, sizeof(ip_hdr));

    // 修改ICMP
    icmp_hdr* rep_icmp = (icmp_hdr*)((uint8_t*)reply->data() + sizeof(ip_hdr) + sizeof(ethernet_hdr));
    rep_icmp->icmp_code = 0;
    rep_icmp->icmp_type = 0;
    rep_icmp->icmp_sum = 0;
    rep_icmp->icmp_sum = cksum((uint8_t*)rep_icmp, packet.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr));

    sendPacket(*reply, outIface->name);
  }
}

void SimpleRouter::handleICMPt3(const Buffer& packet, const std::string& inIface, int type) {
  ethernet_hdr* eth_ptr = (ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));

  /* 查找路由表和ARP cache */
  RoutingTableEntry routing_entry = m_routingTable.lookup(ip_ptr->ip_src);
  auto arp_entry = m_arp.lookup(ip_ptr->ip_src);
  // 如果没有对应的IP/MAC对，将request插入队列
  if (arp_entry == nullptr) {
    m_arp.queueRequest(ip_ptr->ip_src, packet, inIface);
  }
  // 否则，发送echo reply
  else {
    Buffer* reply = new Buffer(sizeof(icmp_t3_hdr) + sizeof(ip_hdr) + sizeof(ethernet_hdr));
    const Interface* outIface = findIfaceByName(routing_entry.ifName);
    
    // 处理以太帧
    ethernet_hdr* rep_eth = (ethernet_hdr*)((uint8_t*)reply->data());
    memcpy(rep_eth, eth_ptr, sizeof(ethernet_hdr));
    memcpy(rep_eth->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
    memcpy(rep_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);

    // 处理IP
    ip_hdr* rep_ip = (ip_hdr*)((uint8_t*)reply->data() + sizeof(ethernet_hdr));
    memcpy(rep_ip, ip_ptr, sizeof(ip_hdr));
    rep_ip->ip_id = 0;
    rep_ip->ip_ttl = 64;
    rep_ip->ip_p = ip_protocol_icmp;
    rep_ip->ip_src = outIface->ip;
    rep_ip->ip_dst = ip_ptr->ip_src;
    rep_ip->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
    rep_ip->ip_sum = 0;
    rep_ip->ip_sum = cksum(rep_ip, sizeof(ip_hdr));

    // 处理ICMP type3
    icmp_t3_hdr* rep_icmp_t3 = (icmp_t3_hdr*)((uint8_t*)reply->data() + sizeof(ip_hdr) + sizeof(ethernet_hdr));
    if (type == 1) {
      rep_icmp_t3->icmp_code = 3;
      rep_icmp_t3->icmp_type = 3;
    }
    else {
      rep_icmp_t3->icmp_code = 0;
      rep_icmp_t3->icmp_type = 11;
    }
    rep_icmp_t3->unused = 0;
    rep_icmp_t3->next_mtu = 0;
    rep_icmp_t3->icmp_sum = 0;
    memcpy((uint8_t*)(rep_icmp_t3->data), (uint8_t*)ip_ptr, ICMP_DATA_SIZE);
    rep_icmp_t3->icmp_sum = cksum(rep_icmp_t3, sizeof(icmp_t3_hdr));

    sendPacket(*reply, outIface->name);
  }
}

void SimpleRouter::handleForward(const Buffer& packet, const std::string& inIface) {
  ip_hdr* ip_ptr = (ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));

  /* 查找路由表和ARP cache */
  RoutingTableEntry routing_entry = m_routingTable.lookup(ip_ptr->ip_dst);
  auto arp_entry = m_arp.lookup(ip_ptr->ip_dst);

  /* 转发 */
  const Interface* outIface = findIfaceByName(routing_entry.ifName);
  Buffer* forward = new Buffer(packet);

  // 设置以太网帧
  ethernet_hdr* fwd_eth = (ethernet_hdr*)((uint8_t*)forward->data());
  memcpy(fwd_eth->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
  memcpy(fwd_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);

  // 设置IP
  ip_hdr* fwd_ip = (ip_hdr*)((uint8_t*)forward->data() + sizeof(ethernet_hdr));
  fwd_ip->ip_ttl--;
  fwd_ip->ip_sum = 0;
  fwd_ip->ip_sum = cksum(fwd_ip, sizeof(ip_hdr));

  sendPacket(*forward, routing_entry.ifName);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  
  /* 检查以太帧的合法性 */
  // 以太帧大小
  if (packet.size() < sizeof(ethernet_hdr)) {
    std::cout << "Ethernet header is truncated, ignoring" << std::endl;
    return;
  }
  // 以太帧类型
  ethernet_hdr* eth_ptr = (ethernet_hdr*)packet.data();
  uint16_t eth_type = ethertype((uint8_t*)eth_ptr);
  if (eth_type != ethertype_arp && eth_type != ethertype_ip) {
    std::cout << "Ethernet frame type is unsupported, ignoring" << std::endl;
    return;
  }
  // 目的地址类型
  if (!memcpy(eth_ptr->ether_dhost, iface->addr.data(), 6)) {
    // 指向路由
    std::cout << "Destination host is the interface MAC address odf router" << std::endl;
  }
  else if ((eth_ptr->ether_dhost[0] &
            eth_ptr->ether_dhost[1] &
            eth_ptr->ether_dhost[2] &
            eth_ptr->ether_dhost[3] &
            eth_ptr->ether_dhost[4] &
            eth_ptr->ether_dhost[5]) == 0xff) {
    // 广播
    std::cout << "Destination host is broadcast address" << std::endl;
  }
  else {
    // 非法目的地址
    std::cout << "Destination host is invalid, ignoring" << std::endl;
  }

  /* 分类型进行处理 */
  // ARP包
  if (eth_type == ethertype_arp) {
    handleArp(packet, inIface);
  }
  // IPv4数据报
  else {
    handleIPv4(packet, inIface);
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
