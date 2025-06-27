#########################################################################
# title: gen_cn_cert.sh                                                 #
# author: Kari Tiirikainen                                              #
# date: 20250627                                                        #
# description: Create and sign a new certificate for a defined CN & OU  #
# usage: ./gen_cn_cert.sh <ca_name> <ou> <cn>                           #
#########################################################################

#!/bin/sh

if [ "$#" -ne 3 ]
then
  echo "Usage: <ca_name> <ou> <cn>"
  exit 1
fi

CA=$1
OU=$2
CN=$3
#FOLDER=.
FOLDER=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

cp  $FOLDER/ca/$CA.cnf  $FOLDER/ca/${CA}${OU}${CN}.cnf
CACONF=$FOLDER/ca/${CA}${OU}${CN}.cnf

sed -i -E "s/(^ou\s+=\s).*/\1$(echo $OU)/" $CACONF
sed -i -E "s/(^cn\s+=\s).*/\1$(echo $CN)/" $CACONF

openssl req -new -config $CACONF -out $FOLDER/certs/$CN.csr -keyout $FOLDER/certs/$CN.key -nodes
openssl ca -config $CACONF -in $FOLDER/certs/$CN.csr -out $FOLDER/certs/$CN.crt
