#!/bin/bash

mkdir CapturedPackets

# Start the ptnet process in the background
cmd="sudo python3 ptnetinspector.py -t $1 -i $2 -n"

if [ "$1" = "p" ]; then
    if [ "$4" != "None" ]; then
        cmd="$cmd -d $4"
    fi

    if [ "$5" == "True" ]; then
        cmd="$cmd -more"
    fi
elif [ "$1" = "a" ]; then
    if [ "$4" == "True" ]; then
        cmd="$cmd -more"
    fi
else
    if [ "$4" != "None" ]; then
        cmd="$cmd -da+ $4"
    fi

    if [ "$5" != "None" ]; then
        cmd="$cmd -prefix $5"
    fi

    if [ "$6" != "None" ]; then
        cmd="$cmd -period $6"
    fi

    if [ "$7" != "None" ]; then
        cmd="$cmd -dns $7"
    fi

    if [ "$8" == "True" ]; then
        cmd="$cmd -more"
    fi
fi

echo -e "\nStarting capturing packets..."

sudo tcpdump -i $2 -w ./CapturedPackets/capPackets.pcapng > ./CapturedPackets/tcpdump_stdout.log &

# Capture the PID of the tcpdump process
pid1=$!

# Start the packet capturing on the et0 interface
#sudo tcpdump -i eth0 not ether src 00:0c:29:b8:a9:4d -e -v -n > capPackets.pcapng &

echo -e "\nStarting analysis..."

$cmd > ./CapturedPackets/ptnetOut.txt 2> ./CapturedPackets/ptnetinspector_stderr.log &

# Capture the PID of the ptnet process
pid2=$!

# Wait until the ptnet process finishes, then finish the packet capturing using the SIGINT signal
wait $pid2 && {
    # Success handling
    #inspectorEndTime=$(date +%H:%M:%S.%N)
    kill -2 $pid1
} || {
    # Error handling
    kill -2 $pid1
}

echo -e "\nFinished capturing packets and extracting data to files..."

echo -e "\nReading all the packets..."

# Added delay so that the capPackets file can close correctly
sleep 1

# Read all the packets (not src MAC addr 00:0c:29:b8:a9:4d) to the text file
tcpdump -r ./CapturedPackets/capPackets.pcapng not ether src $3 -e -n > ./CapturedPackets/ALL_Packets.txt 2> ./CapturedPackets/tcpdump_stderr.log

echo -e "\nReading MLD packets..."
# Read all the MLD report packets
tcpdump -r ./CapturedPackets/capPackets.pcapng not ether src $3 and ip6 and not icmp6 and not udp port 5353 and not udp port 5355 -e -v -n > ./CapturedPackets/MLD_report_Packets.txt 2>> ./CapturedPackets/tcpdump_stderr.log

echo -e "\nReading MDNS packets..."
# Read all the MDNS packets
tcpdump -r ./CapturedPackets/capPackets.pcapng not ether src $3 and udp port 5353 -e -v -n > ./CapturedPackets/MDNS_Packets.txt 2>> ./CapturedPackets/tcpdump_stderr.log

echo -e "\nReading LLMNR packets..."
# Read all the LLMNR packets
tcpdump -r ./CapturedPackets/capPackets.pcapng not ether src $3 and udp port 5355 -e -s0 -vvv -X -n > ./CapturedPackets/LLMNR_Packets.txt  2>> ./CapturedPackets/tcpdump_stderr.log

#echo -e "\nWriting end time to the file..."
#echo $inspectorEndTime > ./CapturedPackets/ptnetEndTime.txt