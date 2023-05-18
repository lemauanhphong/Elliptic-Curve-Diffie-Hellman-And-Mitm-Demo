FROM ubuntu

COPY server.cpp /app

RUN g++ -O3 -std=c++11 -g2 -o server server.cpp -Iinclude -L/app/lib -l:libcryptopp.a

EXPOSE 2808

CMD ["./server", "2808"]