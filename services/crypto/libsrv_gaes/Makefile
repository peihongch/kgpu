
all: srv_gaes
	$(if $(BUILD_DIR), cp libsrv_gaes.so $(BUILD_DIR)/ ) 

srv_gaes: srv_gaes.cu sha1 sha224-256 sha384-512 hmac usha isha
	nvcc -O2 --shared --compiler-options '-fPIC' -rdc=true -o libsrv_gaes.so srv_gaes.cu sha1.o sha224-256.o sha384-512.o usha.o isha.o hmac.o

sha1: sha1.cu
	nvcc -O2 -rdc=true -Xcompiler -fPIC -c sha1.cu

sha224-256: sha224-256.cu
	nvcc -O2 -rdc=true -Xcompiler -fPIC -c sha224-256.cu

sha384-512: sha384-512.cu
	nvcc -O2 -rdc=true -Xcompiler -fPIC -c sha384-512.cu

usha: usha.cu
	nvcc -O2 -rdc=true -Xcompiler -fPIC -c usha.cu

isha: isha.cu
	nvcc -O2 -rdc=true -Xcompiler -fPIC -c isha.cu

hmac: hmac.cu usha
	nvcc -O2 -rdc=true -Xcompiler -fPIC -c hmac.cu

clean:
	rm -f *.o *.so
