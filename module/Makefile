dm-apron-y := dm-verity-target.o dm-verity-apron.o
obj-m += dm-apron.o

all:
	make -C ../linux-5.11.1 M=$(PWD) modules

clean:
	make -C ../linux-5.11.1 M=$(PWD) clean
