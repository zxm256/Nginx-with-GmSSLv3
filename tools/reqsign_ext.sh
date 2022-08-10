#!/bin/bash -x

gmssl sm2keygen -pass 123456 -out rootcakey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 -key rootcakey.pem -pass 123456 -out rootcacert.pem -key_usage keyCertSign -key_usage cRLSign
gmssl certparse -in rootcacert.pem

gmssl sm2keygen -pass 123456 -out cakey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN "Sub CA" -days 3650 -key cakey.pem -pass 123456 -out careq.pem
gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass 123456 -out cacert.pem
gmssl certparse -in cacert.pem

gmssl sm2keygen -pass 123456 -out signkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -days 365 -key signkey.pem -pass 123456 -out signreq.pem
gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 123456 -out signcert.pem
gmssl certparse -in signcert.pem

cat signcert.pem > certs.pem
cat cacert.pem >> certs.pem

gmssl sm2keygen -pass 123456 -out clientkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Client -days 365 -key clientkey.pem -pass 123456 -out clientreq.pem
gmssl reqsign -in clientreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 123456 -out clientcert.pem
gmssl certparse -in clientcert.pem
