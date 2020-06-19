#!/usr/bin/env bash

openssl genrsa -out private_key_intermediate.pem 4096
openssl rsa -pubout -in private_key_intermediate.pem -out public_key.pem

# convert private key to pkcs8 format in order to import it from Java
openssl pkcs8 -topk8 -in private_key_intermediate.pem -inform pem -out private_key.pem -outform pem -nocrypt
rm private_key_intermediate.pem
