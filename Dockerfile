FROM ubuntu:latest

RUN apt-get update && apt-get install -y g++

COPY cryptopp /app

WORKDIR /app