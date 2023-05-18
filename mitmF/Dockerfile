FROM ubuntu

COPY mitm.cpp /app

RUN g++ -O3  -std=c++11 -g2 -o mitm mitm.cpp -Iinclude -L/app/lib -l:libcryptopp.a

EXPOSE 2808

CMD ["./mitm", "2808", "172.22.1.3", "2808"]