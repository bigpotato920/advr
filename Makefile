m1 = Makefile1
m2 = Makefile2

target:
	make -f $(m1)
	make -f $(m2)

clean:
	rm route_engine
	rm arm_route_engine
