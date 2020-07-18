import pyshark;#Wrapper for tshark and used to interpret the data obtained from packet capture.
import collections;
import matplotlib.pyplot as plot#Used for plotting graph.
import numpy as np
cap=pyshark.FileCapture('test.pcapng',only_summaries=True)
protocolList=[]
for packet in cap:
    line=str(packet)#Each packet object (i.e a single line that will have the data of a specific packet we see in wireshark will be typecasted into a string and stored in a variable). 
    formattedLine=line.split(" ")#List of different columns of the packet capture file which will be splitted based on the seperator " "(i.e space) which is the default seperator of that data.
    #print(formattedLine)
    #if(formattedLine[4]=="ARP"):#Extracting all the ARP packet ID's.
    protocolList.append(formattedLine[4])
#print(protocolList)
counter=collections.Counter(protocolList)
plot.style.use('ggplot')
y_pos=np.arange(len(list(counter.keys())))
plot.bar(y_pos,list(counter.values()),align='center',alpha=0.5,color=['b','g','r','c','m'])
plot.xticks(y_pos,list(counter.keys()))
plot.ylabel("Frequency")
plot.xlabel("Protocol name")
plot.show()