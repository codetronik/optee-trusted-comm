#### Secure Communication between devices based on OP-TEE

## Server Build
```
sudo apt-get install clang libssl-dev
cd server
make
./server -init (On the first run)
./server
```

## Client (example)
```
python3 client_example.py
```

## Communication Example
![image](https://raw.githubusercontent.com/codetronik/optee-trusted-comm/master/example.png)
