CXX = g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++11 -Iinclude
TARGET = kuznechik

SRCS = src/main.cpp src/kuznechik.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
