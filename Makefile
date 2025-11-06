TARGET = server
HEADERS = http_app.c http_func.c http_define.c
LIBS = -lssl -lcrypto
SAN   =  -fsanitize=address, undefined, leak  $(SAN) 
CC      = clang
CFLAGS  = -Wall -std=c99 

default: all

all: $(TARGET)

$(TARGET): $(TARGET).c $(HEADERS)
	$(CC) $(CFLAGS) $(LIBS) $(TARGET).c -o $(TARGET)

clean :
	$(RM) $(TARGET)
