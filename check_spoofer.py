import netifaces
from scapy.all import sniff

#threshold value

threshold =10

#Select the interface

av_iface=netifaces.interfaces()
iface=raw_input("Select an interface: {}\n".format(str(av_iface)))


addrs =netifaces.ifaddresses(iface)

try:
    local_ip = addrs[netifaces.AF_INET][0]["addr"]
    broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
except:
    print "Cannot read"
requests =[]
replies_count = {}
notif =[]


def check_spoof(src,mac,dst):
    if dst == broadcast:
        if not mac in replies_count:
            replies_count[mac] =0
    
    if not src in requests and src != local_ip:
        if not mac in replies_count:
            replies_count[mac] =0

        else:
            replies_count[mac]+=1

        if (replies_count[mac]>threshold):
            print "ARP spoofing detected from MAC address: %s"%mac
    else:
        if src in requests:
            requests.remove(src)
     
def packet_filter(packet):
    source = packet.sprintf("%ARP.psrc%")
    dest = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    info=packet.sprintf("%ARP.op%")
    if source == local_ip:
        requests.append(dest)
    if info == 'is-at':
        return check_spoof (source, source_mac, dest)

sniff(filter = "arp", prn = packet_filter, store = 0)
