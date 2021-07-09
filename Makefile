QEMU_DIR ?=
GLIB_INC ?=`pkg-config --cflags glib-2.0`
CXXFLAGS ?= -g -Wall -std=c++14 -march=native -iquote $(QEMU_DIR)/include/qemu/ $(GLIB_INC) -iquote $(QEMU_DIR)/capstone/include/

all: libbbv.so libtracer.so

libbbv.so: bbv.cc
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< -ldl -lrt -lz

libtracer.so: tracer.cc
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< cs_disas.cc -ldl -lrt

clean:
	rm -f *.o libbbv.so libtracer.so
