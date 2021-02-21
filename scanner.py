# All code is written by Max Parkinson or from offical Scapy documentation
# Usage: sudo python3 scanner.py
# All options will be within the script

import sys
from scapy.all import sr1,IP,ICMP,TCP,UDP,sr

#function takes in destination IP and port to scan and returns whether port is open
def singlePortScanner(dstIP, dstPort):
    ans, unans=sr(IP(dst=dstIP)/TCP(flags="S", dport=(dstPort)),timeout=5, verbose=0)
    #checks if answer was received. 
    if ans:
        #prints the type of port and whether or not it's open.
        ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: r.sprintf("%TCP.sport% is open"))
        ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "RA",prn=lambda s,r: r.sprintf("%TCP.sport% is closed"))
    #blocked ports will usually get caught by this.
    else:
        print("Port " + str(dstPort) + " is closed")

#function takes in destination IP and port to scan and returns whether port is open with UDP protocol
#Output is not formatted, just shown as Scapy defaults to.
def singlePortScannerUDP(dstIP, dstPort):
    ans, unans=sr(IP(dst=dstIP)/UDP(dport=(dstPort)),timeout=5, verbose=0)
    ans.show()

#function takes in destination IP along with list of destination ports. Iterates through ports and calls singlePortScanner()
def multiPortScanner(dstIP, dstPorts):
    for x in dstPorts:
        singlePortScanner(dstIP, x)

#default icmp ping from scapy documentation
def icmpPing(dstIP):
    ans, unans = sr(IP(dst=dstIP)/ICMP())
    ans.summary(lambda s,r: r.sprintf("%IP.src% is alive") )

#default tracert from scapy documentation
def tracert(dstIP, dstPort):
    ans, unans = sr(IP(dst=dstIP,ttl=(1,10))/TCP(dport=dstPort,flags="S"), timeout=3)
    ans.summary( lambda s,r: r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}"))
    

#main function

print("\nSelect option: (just the number)")
print("[0] Single host and port (TCP)")
print("[1] Single host and port (UDP)")
print("[2] Single host and multiple ports (TCP)")
print("[3] Send ping to host through ICMP")
print("[4] Send tracert to host and port")

userInput = int(input("Type option and press enter: "))

# All options are simply getting input and entering it in 
if userInput == 0:
    print("Enter IP of host:")
    dstIP = input()
    print("Enter port to scan:")
    dstPort = int(input())
    print("*******************************")
    singlePortScanner(dstIP, dstPort)
    print("*******************************")

elif userInput == 1:
    print("Enter IP of host:")
    dstIP = input()
    print("Enter port to scan:")
    dstPort = int(input())
    print("*******************************")
    singlePortScannerUDP(dstIP, dstPort)
    print("*******************************")


elif userInput == 2:
    dstPorts = []
    print("Enter IP of host:")
    dstIP = input()
    done = 0
    print("Enter each port you would like to scan seperated by ENTER. Type \"done\" when finished.")
    while done !=1:
        userIn = input()
        if (userIn == "done"):
            done = 1
        else:
            dstPorts.append(int(userIn))
    print("*******************************")
    multiPortScanner(dstIP, dstPorts)
    print("*******************************")


elif userInput == 3:
    print("Enter IP of host:")
    dstIP = input()
    icmpPing(dstIP)
    
elif userInput == 4:
    print("Enter IP of host:")
    dstIP = input()
    print("Enter port to scan:")
    dstPort = int(input())
    tracert(dstIP, dstPort)

else:
    print("Bad option. Try again.")