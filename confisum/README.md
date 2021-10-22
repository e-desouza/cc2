This is the binary that executes a sensitive/protected operation.

A new pair of private/public key is generated on startup, and the public key is published
The keys are hex-encoded BTCEC (bitcoin/Koblitz) keys for now

The "confisum" app starts an http server on port 8080 by defaut.
The Dockerfile continues with this default, so the way to use docker is:
```
docker build -t %imageName% .
docker run -p %yourFavPort%:8080 %imageName%
```
