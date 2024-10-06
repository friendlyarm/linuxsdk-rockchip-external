#!/bin/bash

[ -f buildroot_external_libgenmeshlib.tar ] || wget http://112.124.9.243/rockchip/buildroot_external_libgenmeshlib.tar -O buildroot_external_libgenmeshlib.tar
if [ $? -eq 0 ]; then
	tar xvf buildroot_external_libgenmeshlib.tar
fi
