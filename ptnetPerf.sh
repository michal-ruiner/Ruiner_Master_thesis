#!/bin/bash

# Initialize variables for the content of input flags
cmd=""
time=""
runs=3

# Check correct inpuct flags with values
if [ "$#" -ne 4 ] && [ "$#" -ne 6 ]; then
        echo "Wrong flags, the input must be 'sudo ./ptnetPerf -m <mode> -t <time> [-r <runs>]'."
        echo "Flags:"
        echo "  -m : Mode selection (p, a, a+)"
        echo "  -t : Time value (positive integer)"
        echo "  -r : Number of runs (positive integer)"
	exit 1
fi

# Parse the flags and their values
while getopts "m:t:r:" opt; do
	case $opt in
		m)
			if ! [[ "$OPTARG" =~ ^(a|a\+|p)$ ]]; then
				echo "The '-m' flag can have only values 'p', 'a' or 'a+'."
				exit 1
			else
				case "$OPTARG" in
					a)
						echo "Active mode running..."
						cmd="time sudo python3 ptnetinspector.py -t a -i eth0"
						;;
					a+)
						echo "Aggressive mode running..."
						cmd="time sudo python3 ptnetinspector.py -t a+ -i eth0 -da+ 10 -prefix 2001:f:b:f::/64 -period 1"
						;;
					p)
						echo "Passive mode running..."
						cmd="time sudo python3 ptnetinspector.py -t p -i eth0 -d 10"
						;;
				esac
			fi
			;;
		t)
			if ! [[ "$OPTARG" =~ ^[1-9][0-9]*$ ]]; then
				echo "The time value must be a positive integer."
				exit 1
			else
				time="$OPTARG"
			fi
			;;
                r)
                        if ! [[ "$OPTARG" =~ ^[1-9][0-9]*$ ]]; then
                                echo "The number of runs must be a positive integer."
                                exit 1
                        else
                                runs="$OPTARG"
                        fi
                        ;;
		*)
			echo "Wrong flag provided."
			exit 1
			;;
	esac
done

if [ -z "$cmd" ] || [ -z "$time" ]; then
        echo "Compulsory parameters (mode, time) must be set."
        exit 1
fi

rm -f toplog.txt
rm -f ptnettime.txt
for ((i=1; i<=runs; i++));
do
	echo -e "\n#Run $i" >> toplog.txt
	echo -e "\n#Run $i" >> ptnettime.txt
	((eval "$cmd") > output.txt 2>> ptnettime.txt) & ((top -n $time -d 1 | grep "python3") >> toplog.txt) & wait
done
rm -f output.txt

############# AVERAGE RUN TIME
realTime=false
runTimeArray=()
regex='[0-9]+\.[0-9]+'
for line in $(cat ptnettime.txt)
do
        if [ "$realTime" = true ]; 
        then
                runtime_sec=$(echo "$line" | grep -oE "$regex")
		runtime_min=$(echo "$line" | grep -oE '^[0-9]+')
		if [ -n "$runtime_min" ]; then
			runtime_sec=$(echo "$runtime_sec" + "$((runtime_min*60))" | bc)
		fi
                array+=($runtime_sec)
		#echo "Runtime: $runtime_sec"
		realTime=false
        fi
        if [[ $line =~ ^[real] ]]; 
        then
                realTime=true 
        fi 
done

sumRT=0

for elm in "${array[@]}"; do
    sumRT=$(echo "$sumRT + $elm" | bc)
done

averageRT=$(echo "scale=3; $sumRT / ${#array[@]}" | bc)


###################### AVERAGE CPU & RAM USAGE
arrayCPU=()
arrayRAM=()
performance=false
counter=0
for line in $(cat toplog.txt)
do
        if [ "$performance" = true ]
        then
                if [ $counter -eq 0 ]
                then
                        arrayCPU+=($line)
                        ((counter++))

                elif [ $counter -eq 1 ]
                then
                        arrayRAM+=($line)
                        ((counter++))

                else
                        counter=0
                        performance=false
                fi
        fi
        if [[ $line =~ ^[DRSTZ]$ ]]
        then
                performance=true 
        fi 
done

sumCPU=0
for elm in "${arrayCPU[@]}"; do
    sumCPU=$(echo "$sumCPU + $elm" | bc)
done

sumRAM=0
for elm in "${arrayRAM[@]}"; do
    sumRAM=$(echo "$sumRAM + $elm" | bc)
done

averageCPU=$(echo "scale=3; $sumCPU / ${#arrayCPU[@]}" | bc)

averageRAM=$(echo "scale=3; $sumRAM / ${#arrayRAM[@]}" | bc)

echo "####################"
echo "Average runtime: $averageRT s"
echo "Average CPU usage: $averageCPU %"
echo "Average RAM usage: $averageRAM %"
echo -e "####################\n"

rm -f toplog.txt
rm -f ptnettime.txt
