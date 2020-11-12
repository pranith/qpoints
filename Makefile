QEMU_DIR ?=
GLIB_INC ?=`pkg-config --cflags glib-2.0`
CXXFLAGS ?= -g -Wall -std=c++11 -march=native -iquote $(QEMU_DIR)/include/qemu/ $(GLIB_INC)

all: libbbv.so

libbbv.so: bbv.cc
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< -ldl -lrt
