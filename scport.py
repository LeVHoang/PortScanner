import socket
import ipaddress
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def iplist(target):
    target = unicode(target, "utf-8")
    net4 = ipaddress.ip_network(target)
    return net4.hosts()

def itarget(target): 
    ip = target.split('.')
    try:
        int(ip[-1])
        return target
    except:
        return socket.gethostbyname(target)

def ping(host):
    cmd = ['ping', '-w', '1', str(host)]
    p = subprocess.Popen(cmd,stdout=subprocess.PIPE,stdin=subprocess.PIPE,bufsize=100000,stderr=subprocess.PIPE)
    result = p.communicate()[0]
    result = bytes.decode(result)
    if "rtt" in result:
        return host
    return None

def port_scan(host, port):
     cmd ='nc -z -v -w 1 ' + host + ' ' + str(port)
     process = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
     result = bytes.decode(process.stderr.read())
     if 'succeeded' in result:
        print'Port: %s\tState: Open'%(int(port))
     else:
        print'Port: %s\tState: Close'%(int(port))

def main():
    host = raw_input('IP/Domain: ')
    print('--------------------------')
    if('/' in host):
        ilist = iplist(host)
        for x in ilist:
            x = str(x)
            if ping(x) is not None:
                print'Host: %s is up!'%(x)
                print'****'
                for y in range(1, 65535):
                    port_scan(x, y)
            else:
                print'Host: %s is down!'%(x)
            print'******************'
    else:
        host = itarget(host)
        if ping(host) is not None:
            print'Host: %s is up!'%(host)
            print'**********'
            for x in range(1, 65535):
                port_scan(host, x)
        else:
             print'Host: %s is down!'%(host)
main()
