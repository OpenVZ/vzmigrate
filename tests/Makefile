### Compiler flags
CC = gcc
CFLAGS = -g -Wall -fPIC -O0 -pthread -D_GNU_SOURCE
LDFLAGS += -L . -L /usr/kerberos/lib64 -L /usr/lib64

INC = -I. -I/usr/kerberos/include

LIBVER = 1
LIBVER_MINOR=0.1

LOBJ = libvztest.o

LIB_vztest = libvztest.so.$(LIBVER).$(LIBVER_MINOR)
LIB_vztest_major = libvztest.so.$(LIBVER)

BIN = ssh_cli ssh_cli2 ssh_reader sock_cli sock_srv sock_cli2 sock_srv2 ps_mode_cli ps_mode_srv snd_rw snd_rw0 rcv_rw
BIN += snd_ploop rcv_ploop snd_ploop2 rcv_ploop2
#BIN += ssl_cli ssl_srv ssl_cli2 ssl_srv2
all: libvztest.so $(LIB_vztest) $(LIB_vztest_major) libvztest.a $(BIN)

$(LIB_vztest): $(LOBJ)
	$(CC) $(CFLAGS) $(INC) $(LDFLAGS) -shared --as-needed \
	-Wl,-soname=$(LIB_vztest_major) $^ -o $@

libvztest.so: $(LIB_vztest)
	ln -sf $(LIB_vztest) libvztt.so
	ln -sf $(LIB_vztest) $(LIB_vztest_major)

libvztest.a: $(LOBJ)
	ar scq $@ $+
	ranlib $@

ssh_cli: ssh_cli.o util.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

ssh_reader: ssh_reader.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

ssh_cli2: ssh_cli2.o $(PWD)/libvztest.a
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

ssl_cli: ssl_cli.o util.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bstatic -lssl -lcrypto -lkrb5 -lk5crypto -lcom_err -Wl,-Bdynamic -ldl -lresolv -o $@

ssl_srv: ssl_srv.o util.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bstatic -lssl -lcrypto -lkrb5 -lk5crypto -lcom_err -Wl,-Bdynamic -ldl -lresolv -o $@

ssl_cli2: ssl_cli2.o util.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bstatic -lssl -lcrypto -lkrb5 -lk5crypto -lcom_err -Wl,-Bdynamic -ldl -lresolv -o $@

ssl_srv2: ssl_srv2.o util.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bstatic -lssl -lcrypto -lkrb5 -lk5crypto -lcom_err -Wl,-Bdynamic -ldl -lresolv -o $@

sock_srv: sock_srv.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

sock_cli: sock_cli.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

sock_srv2: sock_srv2.o util.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

sock_cli2: sock_cli2.o util.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

ps_mode_srv: ps_mode_srv.o util.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

ps_mode_cli: ps_mode_cli.o util.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

snd_rw: snd_rw.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bdynamic -lpthread -o $@

rcv_rw: rcv_rw.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bdynamic -lpthread -o $@

snd_rw0: snd_rw0.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

snd_ploop: snd_ploop.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bdynamic -lpthread -lvzctl -o $@

rcv_ploop: rcv_ploop.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bdynamic -lpthread -lvzctl -o $@

snd_ploop2: snd_ploop2.o ../bin/ploop.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bdynamic -lpthread -lvzctl -o $@

rcv_ploop2: rcv_ploop2.o ../bin/ploop.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -Wl,-Bdynamic -lpthread -lvzctl -o $@

.c.o:
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

clean:
	rm -rf *.o libvztest.a libvztest.so* $(BIN)

