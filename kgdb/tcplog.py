# python plugin for gdb

import struct

TLB_FLAG_RXBUF =        0x0001  #/* Includes receive buffer info */
TLB_FLAG_TXBUF =        0x0002  #/* Includes send buffer info */
TLB_FLAG_HDR   =        0x0004  #/* Includes a TCP header */
TLB_FLAG_VERBOSE =      0x0008  #/* Includes function/line numbers */
TLB_FLAG_STACKINFO =    0x0010  #/* Includes stack-specific info */

TCP_LOG_BUF_VER =       9   # from netinet/tcp_log_buf.h
TCP_LOG_DEV_TYPE_BBR =  1   # from dev/tcp_log/tcp_log_dev.h

TCP_LOG_ID_LEN  =       64
TCP_LOG_TAG_LEN =       32
TCP_LOG_REASON_LEN =    32

AF_INET =               2
AF_INET6 =              28

INC_ISIPV6 =            0x01

class TCPLogDump(gdb.Command):

    def __init__(self):
        super(TCPLogDump, self).__init__(
            "tcplog_dump", gdb.COMMAND_USER
        )

    def dump_tcpcb(self, tcpcb):
        if tcpcb['t_lognum'] == 0:
            print("processing {}\t{}\n\tno logs".format(tcpcb.type, tcpcb))
            return
        else:
            print("processing {}\t{}".format(tcpcb.type, tcpcb))

        print("\t_t_logstate:\t{} _t_logpoint:\t{} t_lognum:\t{} t_logsn:\t{}".format(
            tcpcb['_t_logstate'], tcpcb['_t_logpoint'], tcpcb['t_lognum'], tcpcb['t_logsn']))
       
        eaddr = (tcpcb['t_logs']['stqh_first'])
        log_buf = bytes()
        while eaddr != 0:
            log_buf += self.print_tcplog_entry(eaddr)
            eaddr = eaddr.dereference()['tlm_queue']['stqe_next']

        if log_buf:
            filename = "{}_tcp_log.bin".format(tcpcb)

            with open(filename, "wb") as f:
                f.write(self.format_header(tcpcb, eaddr, len(log_buf)))
                f.write(log_buf)
            self.logfiles_dumped.append(filename)
            print("\tlog written to {}".format(filename))

    # tcpcb, entry address, length of data for header
    def format_header(self, tcpcb, eaddr, datalen):
        # get a handle we can use to read memory
        inf = gdb.inferiors()[0]    # in a coredump this should always be safe

        # add the common header
        hdrlen = gdb.parse_and_eval("sizeof(struct tcp_log_header)")
        hdr = struct.pack("=llq", TCP_LOG_BUF_VER, TCP_LOG_DEV_TYPE_BBR, hdrlen+datalen)

        inp = tcpcb.cast(gdb.lookup_type("struct inpcb").pointer())

        # add entry->tldl_ie
        bufaddr = gdb.parse_and_eval(
            "&(((struct inpcb *){})->inp_inc.inc_ie)".format(tcpcb))
        length = gdb.parse_and_eval("sizeof(struct in_endpoints)")
        hdr += inf.read_memory(bufaddr, length).tobytes()

        # add boot time
        hdr += struct.pack("=16x") # BOOTTIME

        # add id, tag and reason as UNKNOWN

        unknown = bytes("UNKNOWN", "ascii")

        hdr += struct.pack("={}s{}s{}s"
               .format(TCP_LOG_ID_LEN, TCP_LOG_TAG_LEN, TCP_LOG_REASON_LEN),
               unknown, unknown, unknown
        )

        # add entry->tldl_af
        if inp['inp_inc']['inc_flags'] & INC_ISIPV6:
            hdr += struct.pack("=b", AF_INET6)
        else:
            hdr += struct.pack("=b", AF_INET)

        hdr += struct.pack("=7x") # pad[7]

        if len(hdr) != hdrlen:
            print("header len {} bytes NOT CORRECT should be {}".format(len(hdr), hdrlen))

        return hdr

    def print_tcplog_entry(self, eaddr):
        # implement tcp_log_logs_to_buf
        entry = eaddr.dereference()

        # if header is present copy out entire buffer
        # otherwise copy just to the start of the header
        if entry['tlm_buf']['tlb_eventflags'] & TLB_FLAG_HDR:
            length = gdb.parse_and_eval("sizeof(struct tcp_log_buffer)")
        else:
            length = gdb.parse_and_eval("&((struct tcp_log_buffer *) 0)->tlb_th")

        bufaddr = gdb.parse_and_eval("&(((struct tcp_log_mem *){})->tlm_buf)".format(eaddr))

        # get a handle we can use to read memory
        inf = gdb.inferiors()[0]    # in a coredump this should always be safe
        buf_mem = inf.read_memory(bufaddr, length).tobytes()

        # If needed copy out a header size worth of 0 bytes
        # this was a simple expression untiil gdb got involved
        if not entry['tlm_buf']['tlb_eventflags'] & TLB_FLAG_HDR:
            buf_mem += bytes([0 for b
                in range(
                    gdb.parse_and_eval("sizeof(struct tcp_log_buffer) - {}".format(length))
                )
            ])

        # if verbose is set 
        if entry['tlm_buf']['tlb_eventflags'] & TLB_FLAG_VERBOSE:
            bufaddr = gdb.parse_and_eval("&(((struct tcp_log_mem *){})->tlm_v)".format(eaddr))
            length = gdb.parse_and_eval("sizeof(struct tcp_log_verbose)")
            buf_mem += inf.read_memory(bufaddr, length).tobytes() 

        return buf_mem

    def dump_vnet(self, vnet):
        # this is the general access pattern for something in a vnet
        cmd = "(struct inpcbinfo*)((((struct vnet *) {} )->vnet_data_base) + (uintptr_t )&vnet_entry_tcbinfo)".format(vnet)
        ti = gdb.parse_and_eval(cmd)

        # Get the inplist head (struct inpcb *)(struct inpcbinfo*)({})->ipi_listhead
        inplist = ti['ipi_listhead']
        self.walk_inplist(inplist)

    def walk_inplist(self, inplist):
        inp = inplist['clh_first']
        while inp != 0:
            self.dump_tcpcb(inp.cast(gdb.lookup_type("struct tcpcb").pointer()))
            inp = inp['inp_list']['cle_next']

    def walk_vnets(self, vnet):
        vnets = []
        while vnet != 0:
            vnets.append(vnet)
            vnet = vnet['vnet_le']['le_next']
        return vnets

    def complete(self, text, word):
        return gdb.COMPLETE_SYMBOL

    def invoke(self, args, from_tty):
        if not args:
            self.usage()
            return

        self.logfiles_dumped = []

        node = gdb.parse_and_eval(args)

        # if we get vnet0 pull out the first vnet, it is always there
        if str(node.type) == "struct vnet_list_head *":
            print("finding start of the vnet list and continuing")
            node = node["lh_first"]

        if str(node.type) == "struct vnet *":
            vnets = self.walk_vnets(node)
            for vnet in vnets:
                self.dump_vnet(vnet)

            print("\nprocessed {} vnets, dumped {} logs\n\t{}"
                .format(len(vnets), len(self.logfiles_dumped), " ".join(self.logfiles_dumped)))
        elif str(node.type) == "struct inpcbinfo *":
            # XXX: should work, probably needs testing
            inplist = node['ipi_listhead']
            self.walk_inplist(inplist)

            print("\ndumped {} logs\n\t{}"
                .format(len(self.logfiles_dumped), " ".join(self.logfiles_dumped)))
        elif str(node.type) == "struct tcpcb *":
            # XXX: should work, needs testing
            self.print_tcpcb(node)
        else:
            self.usage()

        return

    def usage(self):
        print("tcplog_dump <address ish>")
        print("Locate tcp_log_buffers and write them to a file")
        print("Address can be one of:")
        print("\tvnet list head (i.e. vnet0)")
        print("\tvnet directly")
        print("\tinpcbinfo")
        print("\ttcpcb")
        print("\nIf given anything other than a struct tcpcb *, will try and walk all available members")
        print("that can be found")
        print("\n")
        print("logs will be written to files in cwd in the format:")
        print("\t\t `%p_tcp_log.bin` struct tcpcb *")
        print("\t\t existing files will be stomped on")
        print("\nexamples:\n")
        print("\t(kgdb) tcplog_dump vnet0")
        print("\t(kgdb) tcplog_dump (struct inpcbinfo *)V_tcbinfo # on a non-vnet kernel (maybe, untested)")
        print("\t(kgdb) tcplog_dump (struct tcpcb *)0xfffff80006e8ca80")
        print("\t\twill result in a file called: 0xfffff80006e8ca80_tcp_log.bin\n\n")

        return

TCPLogDump()
