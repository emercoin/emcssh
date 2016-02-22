CC	?=	cc
LD	= 	$(CC)

CFLAGS	+=	-Wall -I. -I/usr/local/include
LIBS	+=	-L/usr/local/lib -ljansson -lcurl -lpthread
DEPS	=	emcssh.h
OBJ	=	htable.o handle.o reqemc.o main.o 

PROJECT	= 	emcssh

# Default install root
PREFIX	?=	/usr/local

all: $(PROJECT)

.c:.o $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(PROJECT): $(OBJ)
	$(LD) -o $@ $(OBJ) $(LIBS)

clean:
	rm -f $(OBJ) $(PROJECT)

install:
	install -s -m 700 $(PROJECT) $(PREFIX)/sbin
	install -m 600 emcssh_config $(PREFIX)/etc
	mkdir -p $(PREFIX)/man/man8
	install -m 644 emcssh.8 $(PREFIX)/man/man8
