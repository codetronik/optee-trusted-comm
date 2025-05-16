CXX := clang++
CXXFLAGS := -std=c++20 -Wall -Wextra -O2
LDFLAGS := -lssl -lcrypto -pthread

SRC := main.cpp OpenSSLManager.cpp
OBJ := $(SRC:.cpp=.o)
TARGET := myserver

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean

