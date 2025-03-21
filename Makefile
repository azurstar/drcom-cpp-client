# src/Makefile

CXX      := $(TARGET_CXX)
CXXFLAGS := $(TARGET_CXXFLAGS) -std=c++11 -O2
LDFLAGS  := $(TARGET_LDFLAGS) -lssl -lcrypto -lyaml-cpp -lpthread

SRCS := drcom_client.cpp config.cpp utils.cpp
OBJS := $(SRCS:.cpp=.o)

all: drcom_client

drcom_client: $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

# 编译规则
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) drcom_client
