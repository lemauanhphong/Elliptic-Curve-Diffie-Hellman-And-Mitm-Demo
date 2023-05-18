## How to build
```bash
unzip cryptopp.zip
docker build -t ubuntu .
docker compose up
```

## Client sends to server
```bash
docker exec -it <client_container_name> ./client server.local 2808
```

## Modify DNS record to demonstrate DNS poisoning
```bash
Edit `dnsmasq/config/1.local.conf`
docker restart <mitm_container_name> # restart container
```