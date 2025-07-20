import time
import unittest
from scapy.all import sniff
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach
from scapy.packet import Raw
import subprocess
from scapy.sendrecv import send

class ConformanceTests(unittest.TestCase):

    def __init__(self, ia, interface):
        self.ia = ia
        self.interface = interface

    def initialize_dhcpv6(self):
        process = subprocess.Popen(["./dhcomply", self.ia, self.interface])
        return process

    def destroy_dhcpv6(self, process):
        process.kill()

    def _1_1_1a(self):
        proc = self.initialize_dhcpv6()

        print("Listening for DHCPv6 Solicit to ff02::1:2 for 10 seconds...")

        def check_solicit(packet):
            if IPv6 in packet and UDP in packet:
                ipv6 = packet[IPv6]
                udp = packet[UDP]

                if ipv6.dst.lower() == "ff02::1:2" and udp.dport == 547:
                    if Raw in packet and packet[Raw].load[0] == 1:
                        print("[PASS] DHCPv6 Solicit sent to FF02::1:2 detected.")
                        self.destroy_dhcpv6(proc)
                        self.test_passed = True
                        return True

            return False

        # Sniff for up to 10 seconds, stop on success
        packets = sniff(iface=self.interface, filter="udp and ip6", timeout=10, stop_filter=check_solicit)

        if not getattr(self, 'test_passed', False):
            print("[FAIL] No Solicit message sent to FF02::1:2 detected.")
            self.test_passed = False

        self.destroy_dhcpv6(proc)


    def _1_1_1b(self):
        proc = self.initialize_dhcpv6()
        time.sleep(2)  # Let DHCPv6 client initialize

        solicit_pkt = None

        def is_solicit(pkt):
            nonlocal solicit_pkt
            if IPv6 in pkt and UDP in pkt and Raw in pkt:
                if pkt[UDP].dport == 547 and pkt[Raw].load[0] == 1:
                    solicit_pkt = pkt
                    return True
            return False

        print("[*] Listening for Solicit...")
        sniff(iface=self.interface, filter="udp and ip6", timeout=10, stop_filter=is_solicit)

        if not solicit_pkt:
            print("[FAIL] No Solicit received on UDP port 547.")
            self.destroy_dhcpv6(proc)
            return


        client_ip = solicit_pkt[IPv6].src
        print(f"[PASS] Solicit received from {client_ip}")

        advertise = (
                IPv6(dst=client_ip, src="fe80::1") /
                UDP(sport=547, dport=546) /
                Raw(load=b"\x02")
        )
        print("[*] Sending Advertise...")
        send(advertise, iface=self.interface)

        request_pkt = None

        def is_request(pkt):
            nonlocal request_pkt
            if IPv6 in pkt and UDP in pkt and Raw in pkt:
                if pkt[UDP].dport == 547 and pkt[Raw].load[0] == 3:
                    request_pkt = pkt
                    return True
            return False

        print("[*] Listening for Request...")
        sniff(iface=self.interface, filter="udp and ip6", timeout=10, stop_filter=is_request)

        if request_pkt:
            print("[PASS] Request message received after Advertise.")
        else:
            print("[FAIL] No Request message received.")

        self.destroy_dhcpv6(proc)

    def _1_1_1c(self):
        proc = self.initialize_dhcpv6()
        time.sleep(2)

        solicit_pkt = None

        def is_solicit(pkt):
            nonlocal solicit_pkt
            if IPv6 in pkt and UDP in pkt and Raw in pkt:
                if pkt[UDP].dport == 547 and pkt[Raw].load[0] == 1:
                    solicit_pkt = pkt
                    return True
            return False

        print("[*] Listening for Solicit...")
        sniff(iface=self.interface, filter="udp and ip6", timeout=10, stop_filter=is_solicit)

        if not solicit_pkt:
            print("[FAIL] No Solicit received.")
            self.destroy_dhcpv6(proc)
            return

        client_ip = solicit_pkt[IPv6].src
        print(f"[PASS] Solicit received from {client_ip}")

        # Send an Advertise to the wrong port (33536)
        malformed_advertise = (
                IPv6(dst=client_ip, src="fe80::1") /
                UDP(sport=547, dport=33536) /
                Raw(load=b"\x02")
        )
        print("[*] Sending malformed Advertise to port 33536...")
        send(malformed_advertise, iface=self.interface)

        icmp_unreach = None

        def is_icmp_unreachable(pkt):
            nonlocal icmp_unreach
            if IPv6 in pkt and ICMPv6DestUnreach in pkt:
                if pkt[ICMPv6DestUnreach].code == 4:
                    # Check if invoking packet is present and not exceeding 1280 bytes
                    payload_len = len(pkt[ICMPv6DestUnreach].payload)
                    if payload_len <= 1280:
                        icmp_unreach = pkt
                        return True
            return False

        print("[*] Listening for ICMPv6 Destination Unreachable (code 4)...")
        sniff(iface=self.interface, filter="icmp6", timeout=10, stop_filter=is_icmp_unreachable)

        if icmp_unreach:
            src_addr = icmp_unreach[IPv6].src
            if src_addr != "::" and src_addr.startswith("fe80::"):
                print("[FAIL] Source address is link-local, expected unicast.")
            else:
                print("[PASS] ICMPv6 Destination Unreachable received with code 4 and correct size.")
        else:
            print("[FAIL] No ICMPv6 Destination Unreachable (code 4) received.")

        self.destroy_dhcpv6(proc)



if __name__ == '__main__':
    unittest.main()
