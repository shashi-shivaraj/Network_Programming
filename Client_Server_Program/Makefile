# 8th Feb,2018
# Makefile   
# by Shashi Shivaraju

comp_flags = -g -Wall 

mp1: mp1client mp1server

mp1client: mp1client.c
	gcc $(comp_flags) -o mp1client mp1client.c

mp1server: mp1server.c
	gcc $(comp_flags) -o mp1server mp1server.c

clean:
	rm -f mp1client mp1server core

