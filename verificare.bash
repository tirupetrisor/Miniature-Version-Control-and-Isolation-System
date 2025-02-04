#!/bin/bash

# Verificam argumentele scriptului
if [ "$#" -ne 2 ]
then
    echo "Utilizare: $0 <fisier> <director_periculos>"
    exit 1
fi

fisier="$1"
director_periculos="$2"

chmod 777 "$fisier"
if grep -P 'corrupted|dangerous|risk|attack|malware|malicious|[^\x00-\x7F]' "$fisier" > /dev/null || (wc -l "$fisier" < 3 && wc -c "$fisier" > 2000 && wc -w "$fisier" > 1000)
then
    echo "$fisier"
else
    echo "SAFE"
fi
