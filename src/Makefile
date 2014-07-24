# LiME - Linux Memory Extractor
# Copyright (c) 2011-2013 Joe Sylve - 504ENSICS Labs
#
#
# Author:
# Joe Sylve       - joe.sylve@gmail.com, @jtsylve
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

# This is a sample Makefile for cross-compiling the LiME LKM

obj-m := ripper.o
ripper-objs := tcp.o disk.o main.o

KDIR_GOLD := /home/txia/dev/goldfish/
#KVER := $(shell uname -r)

PWD := $(shell pwd)
CCPATH := /home/txia/dev/android-ndk-r9/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86_64/bin

default:
	# cross-compile for Android emulator	
	$(MAKE) ARCH=arm CROSS_COMPILE=$(CCPATH)/arm-linux-androideabi- -C $(KDIR_GOLD) M=$(PWD) modules
	$(CCPATH)/arm-linux-androideabi-strip --strip-unneeded ripper.ko
	
	$(MAKE) tidy

tidy:
	rm -f *.o *.mod.c Module.symvers Module.markers modules.order \.*.o.cmd \.*.ko.cmd \.*.o.d
	rm -rf \.tmp_versions

clean:
	$(MAKE) tidy
	rm -f *.ko 
