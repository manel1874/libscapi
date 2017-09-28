#! /bin/bash
for i in `seq 0 1 2`;
do
        ./GMW -partyID $i -circuitFileName $1 -partiesFileName $2 -inputfileName AesInputs${i}.txt -numThreads $3 &
        echo "Running $i..."
done

