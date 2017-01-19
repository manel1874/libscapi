#! /bin/bash
for i in `seq 0 1 $1`;
do
        ./GMW $i $2 Parties AesInputs$i.txt $3 &
        echo "Running $i..."
done

