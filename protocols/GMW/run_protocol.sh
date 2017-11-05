#! /bin/bash
for i in `seq ${1} 1 ${2}`;
do
    ./GMW -partyID ${i} -circuitFileName ${3} -partiesFileName ${4} -inputFileName ${5} -numThreads ${6} -repetitionId ${7} &
    echo "Running $i..."
done

