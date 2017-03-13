#! /bin/bash
for i in `seq $1 1 $2`;
do
        ./GMW $i $3 Parties AesInputs$i.txt $4 &
        echo "Running $i..."
done

