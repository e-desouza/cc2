This is just a mockup of a Confidential Computing client functionalities.
Interaction requires:
1) Setting the "Session public key" (the public key published by the enclave) - to encrypt the message via ECIES
2) Setting the local private key  - to sign the message


The keys are hex-encoded BTCEC (bitcoin/Koblitz) keys for now

The "encryptor" app starts an http server on port 8090 by defaut.
The Dockerfile continues with this default, so the way to use docker is:
```
docker build -t %imageName% .
docker run -p %yourFavPort%:8090 %imageName%
```
