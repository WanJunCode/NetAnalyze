all: demo


demo: main.cpp HashCalc.cpp SessMgr.cpp Packet.cpp Log.cpp Tool.cpp
	clang++ $^ -o $@ -lpcap -lpthread -llog4cpp -g


.PHONY:clean
clean:
	rm -rf demo core* *.out output/*
