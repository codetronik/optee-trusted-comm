secure communication between devices based on OP-TEE

### Server Build
```
sudo apt-get install clang libssl-dev
cd server
make
./server -init (On the first run)
./server
```

### Client (example)
```
./client_example.py
```
