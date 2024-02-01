# tcplog_dumper

Gather the data from the [FreeBSD's tcp_log device](https://reviews.freebsd.org/rS331347).

## Usage example

Using a FreeBSD -head (r363032 minimum, to have the extra TCP stack headers installed),
compile a new kernel with BBR and extra TCP stack enabled:
```
# cat /usr/src/sys/amd64/conf/BBR
include GENERIC-NODEBUG

ident           BBR
options         TCPHPTS
options         RATELIMIT
makeoptions     WITH_EXTRA_TCP_STACKS=1

# cat /etc/src.conf
KERNCONF=BBR
MALLOC_PRODUCTION=yes
```

Build and install this customized kernel.
Checking for those files
* /boot/kernel/tcp_bbr.ko
* /boot/kernel/tcp_rack.ko

Load thoses modules during startup (sooner on /boot/loader.conf or later on /etc/rc.conf).
Example with the rc.conf:
```sysrc kld_list+="tcp_rack tcp_bbr"```

Configure the system to use BBR TCP stack by default:
```
echo 'net.inet.tcp.functions_default=bbr' >> /etc/sysctl.conf
```

Reboot and check if the system is using the BBR TCP stack:
```
# sysctl net.inet.tcp.functions_default
net.inet.tcp.functions_default: bbr
```

Enable BBR logging for all TCP sessions:

```
# sysctl net.inet.tcp.bb.log_auto_mode=4
# sysctl net.inet.tcp.bb.log_auto_all=1
# sysctl net.inet.tcp.bb.log_auto_ratio=1
```

Start tcplog_dumper:

```
# mkdir /var/log/tcplog_dumps
# chown nobody /var/log/tcplog_dumps
# tcplog_dumper
```

For each new TCP sessions, there will be multiples .pcapng files in the log directory:
You can use [read_bbrlog](https://github.com/Netflix/read_bbrlog) to interpret those files.

## Extracting logs using the kgdb script

TCP Logs can be extracted from FreeBSD kernel core dumps using the gdb plugin
provided in the `kgdb` directory. An example usage assuming relevant kernel
builds and coredumps looks like:

    $ kgdb kernel-debug/kernel.debug vmcore.last
	GNU gdb (GDB) 13.2 [GDB v13.2 for FreeBSD]
	Copyright (C) 2023 Free Software Foundation, Inc.
	License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
	This is free software: you are free to change and redistribute it.
	There is NO WARRANTY, to the extent permitted by law.
	Type "show copying" and "show warranty" for details.
	This GDB was configured as "x86_64-portbld-freebsd15.0".
	Type "show configuration" for configuration details.
	For bug reporting instructions, please see:
	<https://www.gnu.org/software/gdb/bugs/>.
	Find the GDB manual and other documentation resources online at:
		<http://www.gnu.org/software/gdb/documentation/>.

	For help, type "help".
	Type "apropos word" to search for commands related to "word"...
	Reading symbols from coredump/kernel-debug/kernel.debug...

	Unread portion of the kernel message buffer:
	KDB: enter: sysctl debug.kdb.enter

	__curthread () at /usr/src/sys/amd64/include/pcpu_aux.h:57
	57              __asm("movq %%gs:%P1,%0" : "=r" (td) : "n" (offsetof(struct pcpu,
	(kgdb) source tcplog.py
	(kgdb) tcplog_dump vnet0
	processing struct tcpcb *       0xfffff80006e8ca80
			_t_logstate:    4 _t_logpoint:  0 '\000' t_lognum:      25 t_logsn:     25
			log written to 0xfffff80006e8ca80_tcp_log.bin
	processing struct tcpcb *       0xfffff8000ec2b540
			_t_logstate:    4 _t_logpoint:  0 '\000' t_lognum:      8 t_logsn:      8
			log written to 0xfffff8000ec2b540_tcp_log.bin
	processing struct tcpcb *       0xfffff80006bd9540
			no logs
	processing struct tcpcb *       0xfffff80006bd9a80
			no logs
	processing struct tcpcb *       0xfffff8001d837540
			no logs
	processing struct tcpcb *       0xfffff8001d837000
			no logs

	processed 1 vnets, dumped 2 logs
			0xfffff80006e8ca80_tcp_log.bin 0xfffff8000ec2b540_tcp_log.bin


The generated files can be given to tcplog_dumper to generate pcaps like so:

	$ tcplog_dumper -s -f 0xfffff80006e8ca80_tcp_log.bin

