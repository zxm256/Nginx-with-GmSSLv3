#!/bin/bash -x


# 这里我们需要生成两个证书，一个是签名证书，一个加密证书，用相同的CA证书签名
# 这两个证书的CN是一样的吗？应该是一样的吧，只是密钥不同，并且KeyUsage不同


# generate a req and sign by ca certificate
gmssl sm2keygen -pass 123456 -out cakey.pem -pubout capubkey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN CA -days 365 -key cakey.pem -pass 123456 -out cacert.pem
gmssl certparse -in cacert.pem

gmssl sm2keygen -pass 123456 -out signkey.pem -pubout signpubkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Alice -days 365 -key signkey.pem -pass 123456 -out signreq.pem
gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 123456 -out signcert.pem
gmssl certparse -in signcert.pem

gmssl sm2keygen -pass 123456 -out enckey.pem -pubout encpubkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Alice -days 365 -key enckey.pem -pass 123456 -out encreq.pem
gmssl reqsign -in encreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 123456 -out enccert.pem
gmssl certparse -in enccert.pem
