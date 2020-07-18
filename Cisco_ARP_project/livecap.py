import sys
import logging
import subprocess
import pyshark
from datetime import datetime
from pygal import XY
from pygal.style import LightSolarizedStyle
logging.getLogger().setLevel(logging.DEBUG)
logger=logging.getLogger(__name__)

def ARP_Request(filename):
    #to filter and extract all ARP request packets from .pcap file which was given as input.
    # tcpdump command that can be used directly in terminal to perform this operation=>
    # sudo tcpdump -r filename.pcap arp[7]=1 -n -vvv
    # '-r' indicates to apply the mentioned filter to .pcap file adjacent to it.
    # '-n' indicates that name resolution for IP addresses is not needed.
    # '7' is the offset of 1byte(out of 2 bytes) which contains the opcode of the corresponding arp packet.
    # '1' is the opcode that indicates the the corresponding packet is an arp_request packet.
    # So collectively 'arp[1]' indicates tcpdump to filter arp_request packets.
    logger.info('Filtering arp_request packets')
    out=subprocess.Popen(['tcpdump','-r',filename,'arp[7]=1','-n','-vvv'],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    stdout,stderr=out.communicate()
    stdout=stdout.decode('utf-8')
    stdout=stdout.replace('=','')
    print(stdout)
    return stdout
def ARP_Response(filename):
    #to filter and extract all ARP response packets from .pcap file which was given as input.
    # tcpdump command that can be used directly in terminal to perform this operation=>
    # sudo tcpdump -r filename.pcap arp[7]=2 -n -vvv
    # '-r' indicates to apply the mentioned filter to .pcap file adjacent to it.
    # '-n' indicates that name resolution for IP addresses is not needed.
    # '7' is the offset of 1byte(out of 2 bytes) which contains the opcode of the corresponding arp packet.
    # '2' is the opcode that indicates the the corresponding packet is an arp_response packet.
    # So collectively 'arp[1]' indicates tcpdump to filter arp_request packets.
    logger.info('Filtering arp_response packets')
    out=subprocess.Popen(['tcpdump','-r',filename,'arp[7]=2','-n','-vvv'],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    stdout,stderr=out.communicate()
    stdout=stdout.decode('utf-8')
    stdout=stdout.replace('=','')
    print(stdout)
    return stdout
def main():
    if len(sys.argv)!=2:
        logger.error('Insufficient number of arguments')
        print("Usage: <script_name>.py <file_name>.pcap")
        sys.exit(1)

    filename=sys.argv[1]
    req_op=ARP_Request(filename)
    res_op=ARP_Response(filename)
    htmlFile=open("ARP_analysis_result.html",'w')
    htmlFile.write('</pre>')
    htmlFile.write('<h2>ARP_REQUEST_PACKETS</h2>')
    htmlFile.write(req_op)
    htmlFile.write('<h2>ARP_RESPONSE_PACKETS</h2>')
    htmlFile.write(res_op)
    htmlFile.write('</pre>')
if __name__=="__main__":
    main()