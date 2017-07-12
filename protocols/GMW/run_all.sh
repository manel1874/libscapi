#! /bin/bash
for i in `seq 0 1 2`;
do
        ./GMW $i $1 Parties $2 $3 &
        echo "Running $i..."
done

