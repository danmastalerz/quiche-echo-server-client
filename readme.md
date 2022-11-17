# Quiche - echo server and client
## Building
As I've modified the example, for me, the easiest way to build, is to configure everything as in https://github.com/cloudflare/quiche and then
install requirements from https://github.com/cloudflare/quiche/tree/master/quiche/examples. Then just copy these files
into the "examples" folder and run "Make" :) Of course, that is not neccessary, if you have already built
the library responsible for C Api and have the quiche.h header you can just link it and compile it directly.

## Running
```asm
./server host port
./client host port
```