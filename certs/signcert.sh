pwd
ls
mkdir -p demoCA/newcerts
touch demoCA/index.txt
echo '01' > demoCA/serial
CA_INPUT=$MITMPROXY_CERT_PATH/mitmproxy-ca.pem
CA_CERT=mitmproxy-ca.cert
CA_KEY=mitmproxy-ca.key
MY_CERT=mycert.pem
MY_KEY=mycert.key
MY_CERT_SIGNED=mycert.signed.pem
CERTCHAIN=certchain.pem
openssl pkey -in $CA_INPUT -out $CA_KEY #get CA private key
openssl x509 -outform pem -in $CA_INPUT -out $CA_CERT #get only the cert from mitmproxy's pem-file
openssl req -x509 -batch -newkey rsa:2048 -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=prod.de.tbs.toys" -keyout $MY_KEY -out $MY_CERT -nodes #create cert
openssl ca -batch -policy policy_anything -keyfile $CA_KEY -cert $CA_CERT -ss_cert $MY_CERT -out $MY_CERT_SIGNED -days 10000 -extensions v3_req -extfile alt.txt #sign cert with mitmproxys ca
cat $MY_CERT_SIGNED $CA_CERT> $CERTCHAIN #merge root ca with signed certificat
rm -rf demoCA
#test
openssl verify -verbose -CAfile $CA_CERT $CERTCHAIN
if [ $? -ne 0 ]
then
  echo "Something went wrong while creating the cert for nginx."
	exit 1
fi
cp $CERTCHAIN $NGINX_CERT_FOLDER/mitmproxy-ca-signed.pem
cp $MY_KEY $NGINX_CERT_FOLDER/mitmproxy-ca-signed.pem.key
#TODO: The box doesn't work with the ca.der generated from mitmproxy-ca.pem with this setup, use one generated with the signed cert:
#openssl x509 -in certchain.pem -out ca.der -outform DER 

