# luksd

Full-disk encryption for servers

## Protocol

`luksd` protocol is detailed in [PROTOCOL.md](./PROTOCOL.md).

## Building tpm2 static binary

```
docker build -t tpm2-build --file - . < tpm2.Dockerfile
docker run -v "${PWD}:/output:Z" -it tpm2-build
```
