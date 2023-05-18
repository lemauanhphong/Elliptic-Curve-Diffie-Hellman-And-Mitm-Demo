FROM ubuntu

COPY client.cpp /app

RUN g++ -O3 -std=c++11 -g2 -o client client.cpp -Iinclude -L/app/lib -l:libcryptopp.a

CMD ["tail", "-f", "/dev/null"]
