#!/bin/bash

mkdir randomtests
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > randomtests/badFile

for i in {1..5};
do
    echo $(head /dev/random) 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > randomtests/randomBadFile$i
done