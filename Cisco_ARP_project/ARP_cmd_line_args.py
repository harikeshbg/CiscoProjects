import sys
import subprocess
import logging
import pyshark#Wrapper for tshark and used to interpret the data obtained from packet capture.
import pygal
logging.getLogger().setLevel(logging.DEBUG)
logger=logging.getLogger(__name__)
htmlFile=open("new_result_file.html",'w')
def dislplay_type_of_arp_packet(filename):
    # -Y indicates to display the output in wireshark format
    # -e is used to denote that adjacent field has to be extracted from .pcap file
    Out = subprocess.Popen(['tshark', '-r', filename, '-Y', 'arp', '-T', 'fields','-e','arp.src.proto_ipv4', '-e', 'arp.proto.type','-e','arp.hw.type'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = Out.communicate()
    stdout = stdout.decode('utf-8')
    stdout=stdout.replace('\n','<br/>\n')
    stdout=stdout.replace('0x00000800','IPV4')
    #stdout=stdout.replace('1','Ethernet')
    return stdout


def display_request_packets(filename):
    # to filter and extract all ARP request packets from .pcap file which was given as input.
    # tcpdump command that can be used directly in terminal to perform this operation=>
    # sudo tcpdump -r filename.pcap arp[7]=1 -n -vvv
    # '-r' indicates to apply the mentioned filter to .pcap file adjacent to it.
    # '-n' indicates that name resolution for IP addresses is not needed.
    # '7' is the offset of 1byte(out of 2 bytes) which contains the opcode of the corresponding arp packet.
    # '1' is the opcode that indicates the the corresponding packet is an arp_request packet.
    # So collectively 'arp[1]' indicates tcpdump to filter arp_request packets.
    logger.info('Filtering arp_request packets')
    out = subprocess.Popen(['tcpdump', '-r', filename, 'arp[7]=1', '-n', '-vvv'],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    stdout, stderr = out.communicate()
    stdout = stdout.decode('utf-8')
    stdout = stdout.replace('=', '')
    stdout = stdout.replace('\n', '<br/>\n')
    htmlFile.write('<center>')
    htmlFile.write('<br><br><h2>' + 'REQUEST_PACKETS:' + '</h2><br><br>')
    htmlFile.write(stdout)
    htmlFile.write('</center>')


def display_response_packets(filename):
    # to filter and extract all ARP response packets from .pcap file which was given as input.
    # tcpdump command that can be used directly in terminal to perform this operation=>
    # sudo tcpdump -r filename.pcap arp[7]=2 -n -vvv
    # '-r' indicates to apply the mentioned filter to .pcap file adjacent to it.
    # '-n' indicates that name resolution for IP addresses is not needed.
    # '7' is the offset of 1byte(out of 2 bytes) which contains the opcode of the corresponding arp packet.
    # '2' is the opcode that indicates the the corresponding packet is an arp_response packet.
    # So collectively 'arp[1]' indicates tcpdump to filter arp_request packets.
    logger.info('Filtering arp_response packets')
    out = subprocess.Popen(['tcpdump', '-r',filename, 'arp[7]=2', '-n', '-vvv'],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    stdout, stderr = out.communicate()
    stdout = stdout.decode('utf-8')
    stdout = stdout.replace('=', '')
    stdout = stdout.replace('\n', '<br/>\n')
    htmlFile.write('<center>')
    htmlFile.write('<br><br><h2>' + 'RESPONSE_PACKETS:' + '</h2><br><br>')
    htmlFile.write(stdout)
    htmlFile.write('</center>')


def get_request_and_response_count(cap):
    req_count=0
    res_count=0
    for packet in cap:
        if(int(packet.arp.opcode)==1):
            req_count+=1
        elif(int(packet.arp.opcode)==2):
            res_count+=1
    return req_count,res_count

def getProtocolPlot(filename):
    tcap = pyshark.FileCapture(filename, only_summaries=True)
    protocolList = {}
    for packet in tcap:
        line = str(packet)  # Each packet object (i.e a single line that will have the data of a specific packet we see in wireshark will be typecasted into a string and stored in a variable).
        formattedLine = line.split(" ")  # List of different columns of the packet capture file which will be splitted based on the seperator " "(i.e space) which is the default seperator of that data.
        # print(formattedLine)
        # if(formattedLine[4]=="ARP"):#Extracting all the ARP packet ID's.
        if (formattedLine[4] in protocolList.keys()):
            protocolList[formattedLine[4]] += 1
        else:
            protocolList.update({formattedLine[4]: 0})
    arp_packet_count=protocolList["ARP"]
    line_chart=pygal.HorizontalBar()
    line_chart._title="Packet count"
    for i in protocolList:
        line_chart.add(i,int(protocolList[i]))
    chart = line_chart.render()
    #print(chart)
    html = """{}""".format(chart)
    return html,arp_packet_count

def displayFun(dictobj):
    for i in dictobj:
        htmlFile.write('<tr>')
        htmlFile.write('<td>' + str(i) + '</td>')
        htmlFile.write('<td>' + str(dictobj[i]) + '</td>')
        htmlFile.write('</tr>')
def displayCacheAndCount(cap):
    dict = {}
    countdict = {}
    for packet in cap:
        if (int(packet.arp.opcode) == 2):
            #print("packet:number: ", packet.number)
            ip_addr = packet.arp.src.proto_ipv4
            resolved_mac_addr = packet.arp.src.hw_mac
            dict.update({ip_addr: resolved_mac_addr})
        if(int(packet.arp.opcode)==1):
            ip_dst_addr = packet.arp.dst.proto_ipv4
            if (ip_dst_addr in countdict.keys()):
                countdict[ip_dst_addr] += 1
            else:
                countdict.update({ip_dst_addr: 0})
            #print("IP_address =", ip_addr, ",Resolved_mac_address=", resolved_mac_addr)
    #print(dict)
    #print(countdict)
    htmlFile.write('<center>')
    htmlFile.write('<h2>ARP-CACHE</h2>')
    htmlFile.write('<table border="1">')
    htmlFile.write('<tr>')
    htmlFile.write('<th>' + "IP_Address" + '</th>')
    htmlFile.write('<th>' + "Resolved_MAC_Address" + '</th>')
    htmlFile.write('</tr>')
    displayFun(dict)
    htmlFile.write('</table><br><br>')

    htmlFile.write('<h2>REQUEST_COUNT</h2>')
    htmlFile.write('<table border="1">')
    htmlFile.write('<tr>')
    htmlFile.write('<th>' + "IP_Address" + '</th>')
    htmlFile.write('<th>' + "Count" + '</th>')
    htmlFile.write('</tr>')
    displayFun(countdict)
    htmlFile.write('</table><br><br>')
    htmlFile.write('</center>')

def main():
    if len(sys.argv)!=2:
        logger.error('Insufficient number of arguments')
        print("Usage: <script_name>.py <file_name>.pcap")
        sys.exit(1)

    filename=sys.argv[1]
    cap = pyshark.FileCapture(filename, display_filter='arp', use_json=True)
    image, arp_count = getProtocolPlot(filename)
    request_count, response_count = get_request_and_response_count(cap)
    htmlFile.write('<center>')
    htmlFile.write('<h1>' + '<u>' + "ARP-ANALYSIS" + '</u>' + '</h1><br><br><br>')
    htmlFile.write('<h2>' + 'Frequencies of different protocols during packet capture:' + '</h2>')
    htmlFile.write(image)
    htmlFile.write('<br><br>' + "Total number of ARP packets captured: " + '<b>' + str(arp_count + 1) + '</b>')
    htmlFile.write('<br><br>' + "Total number of ARP_request packets captured: " + '<b>' + str(request_count) + '</b>')
    htmlFile.write(
        '<br><br>' + "Total number of ARP_response packets captured: " + '<b>' + str(response_count) + '</b><br><br>')
    displayCacheAndCount(cap)
    htmlFile.write('<br><br><h2>' + 'Protocol and hardware types of arp packets:' + '</h2>')
    htmlFile.write('<pre>')
    htmlFile.write(dislplay_type_of_arp_packet(filename))
    htmlFile.write('</pre>')
    htmlFile.write('<br><br><center><h1><u>' + 'RAW-DATA' + '</u></h1></center>')
    htmlFile.write('<pre>')
    display_request_packets(filename)
    display_response_packets(filename)
    htmlFile.write('</pre>')
    htmlFile.write('</center>')
if __name__=="__main__":
    main()