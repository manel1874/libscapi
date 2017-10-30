#! /bin/bash
for i in `seq $1 1 $2`;
do
        ./GMW $i $3 $4 AesInputs$i.txt $5 &
        echo "Running $i..."
done

