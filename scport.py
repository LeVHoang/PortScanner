# Code chay tren python2. Can cai dat them nmap va ipaddress
import nmap
import socket
import ipaddress

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def iplist(target):
    target = unicode(target, "utf-8")
    net4 = ipaddress.ip_network(target)
    return net4.hosts()

def itarget(target): 
    ip = target.split(".")
    try:
        int(ip[-1])
        return target
    except:
        return socket.gethostbyname(target)

nm = nmap.PortScanner()

def nscan_port(host):
    try:
        host = unicode(host, 'utf-8')
        s = nm.scan(host)
        if s['scan'] == {}:
            print('IP: %s\tStatus: %s' % (host, 'down'))
            return
        status = nm[host].state()
        if(str(status)=='up'):
            print('----------------------------------------------------')
            print('Host : %s' % (host))
            print('State : %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('Protocol : %s' % proto)
                lport = nm[host][proto].keys()
                lport.sort()
                for port in lport:
                    print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
            print('----------------------------------------------------')
    except:
        print('! ERROR')

def main():
    host = raw_input('IP/Domain: ')
    print('--------------------------')
    if('/' in host):
        ilist = iplist(host)
        for x in ilist:
            x = str(x)
            nscan_port(x)
    else:
        host = itarget(host)
        nscan_port(host)


main()
