#########################################################################
# title: sign_csr.sh                                                    #
# author: Kari Tiirikainen                                              #
# date: 20250627                                                        #
# description: Sign a certificate signing request                       #
# usage: ./sign_csr.sh <ca_name> <reqfile>                              #
#########################################################################

#!/bin/sh

if [ "$#" -ne 2 ]
then
  echo "Usage: <ca_name> <reqfile>"
  exit 1
fi

CA=$1
CSR=$2
#FOLDER=.
FOLDER=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DOMAIN=$( openssl req -in ${CSR} -noout -subject | awk '{ gsub(",",""); print $3 }')

echo "Signing request for $DOMAIN"
sed -i -E "s/(^fqdn\s+=\s).*/\1$(echo $DOMAIN | sed -E "s/[Ww]ildcard/\*/")/" $FOLDER/ca/$CA.cnf

openssl ca -config $FOLDER/ca/$CA.cnf -in ${CSR} -out $FOLDER/certs/$DOMAIN.crt

openssl x509 -in $FOLDER/certs/$DOMAIN.crt
