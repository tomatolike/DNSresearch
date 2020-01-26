tshark -r output.pcap -T json > output.json
tshark -r output.pcap -T text > output1.txt
cat output1.txt | egrep -v "TCP" > output2.txt