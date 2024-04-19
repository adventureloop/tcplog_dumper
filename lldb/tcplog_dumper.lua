-- lldb lua script to extract logs from tcpcbs in a crash dump

TLB_FLAG_RXBUF =        0x0001  --#/* Includes receive buffer info */
TLB_FLAG_TXBUF =        0x0002  --#/* Includes send buffer info */
TLB_FLAG_HDR   =        0x0004  --#/* Includes a TCP header */
TLB_FLAG_VERBOSE =      0x0008  --#/* Includes function/line numbers */
TLB_FLAG_STACKINFO =    0x0010  --#/* Includes stack-specific info */
        
TCP_LOG_BUF_VER =       9   --# from netinet/tcp_log_buf.h
TCP_LOG_DEV_TYPE_BBR =  1   --# from dev/tcp_log/tcp_log_dev.h

TCP_LOG_ID_LEN  =       64
TCP_LOG_TAG_LEN =       32
TCP_LOG_REASON_LEN =    32
        
AF_INET =               2
AF_INET6 =              28
        
INC_ISIPV6 =            0x01

function tcplog_format_hdr(tcpcb, inpcb, datalen)
	hdrlen = lldb.target:FindFirstType("struct tcp_log_header")
		   :GetByteSize()

	-- https://www.lua.org/manual/5.3/manual.html#6.4.2
	hdr = string.pack("=I4I4I8", TCP_LOG_BUF_VER, TCP_LOG_DEV_TYPE_BBR,
		hdrlen+datalen)

	-- add inp_inc.inc_ie
	incie = inpcb:GetChildMemberWithName("inp_inc")
		      :GetChildMemberWithName("inc_ie")
		      :GetLoadAddress()

	err = lldb.SBError()	-- leaving this here as an example
	hdr = hdr .. lldb.process:ReadMemory(incie, 
		lldb.target:FindFirstType("struct in_endpoints"):GetByteSize(),
		err
	)

	-- add boot time as 16 zero bytes
	hdr = hdr .. string.pack("=xxxxxxxxxxxxxxxx")

	-- add Log values
	hdr = hdr .. string.pack(string.format("=c%dc%dc%d",
		TCP_LOG_ID_LEN, TCP_LOG_TAG_LEN, TCP_LOG_REASON_LEN),
		"UNKNOWN", "UNKNOWN", "UNKNOWN")

	-- add AF
	incflags = inpcb:GetChildMemberWithName("inp_inc")
			:GetChildMemberWithName("inc_flags")
			:GetValueAsUnsigned()
	if (incflags & INC_ISIPV6) ~= 0 then
		hdr = hdr .. string.pack("=I1", AF_INET6)
	else
		hdr = hdr .. string.pack("=I1", AF_INET)
	end

	-- add pad (uint8_t pad[7])
	hdr = hdr .. string.pack("=xxxxxxx")
	return hdr
end

function tcplog_format_entry(entry)

	flags = entry:GetChildMemberWithName("tlm_buf")
		     :GetChildMemberWithName("tlb_eventflags")
		     :GetValueAsUnsigned()

	logbuflen = lldb.target:FindFirstType("struct tcp_log_buffer")
			       :GetByteSize()

	if flags & TLB_FLAG_HDR ~= 0 then
		length = logbuflen
	else
		length = logbuflen - lldb.frame:EvaluateExpression(
			"&((struct tcp_log_buffer *) 0)->tlb_th")
				   :GetValueAsSigned()
	end

	-- get tlm_buf
	tlmbufaddr = entry:GetChildMemberWithName("tlm_buf")
		      :GetLoadAddress()
	logbuf = lldb.process:ReadMemory(tlmbufaddr, length, lldb.SBError())

	-- if we don't have a header add header size of 0 bytes
	if flags & TLB_FLAG_HDR == 0 then
		for i=1, 
			(lldb.target:FindFirstType("struct tcp_log_buffer")
				    :GetByteSize() - length) do
			logbuf = logbuf .. string.pack("=x")
		end
	end

	-- get tlm_v if it is there
	if flags & TLB_FLAG_VERBOSE ~= 0 then
		tlmvaddr = entry:GetChildMemberWithName("tlm_v")
			      :GetLoadAddress()
		logbuf = logbuf .. lldb.process:ReadMemory(tlmvaddr,
			lldb.target:FindFirstType("struct tcp_log_verbose")
				   :GetByteSize(),
			lldb.SBError()
		)
	end
	return logbuf
end

function walk_vnets(vnet)
	vnets = {}
	while vnet:GetValueAsSigned() ~= 0 do
		table.insert(vnets, vnet)
		vnet = vnet:GetChildMemberWithName("vnet_le")
			   :GetChildMemberWithName("le_next")
	end
	return vnets
end

function walk_inplist(inp)
	inplist = {}
	while inp:GetValueAsSigned() ~= 0 do
		table.insert(inplist, inp)
		inp = inp:GetChildMemberWithName("inp_list")
			 :GetChildMemberWithName("cle_next")
	end
	return inplist
end

-- 
-- Accessing vnet members takes the form:
-- (struct inpcbinfo*)((((struct vnet *) vnet0 )->vnet_data_base) + (uintptr_t )&vnet_entry_tcbinfo)
-- While we could feed this directly to EvaluateExpression (as we do with gdb),
-- but lldb offers us a better form for constructing the final value.
--
-- We are expecting the full vnet member name, i.e. vnet_entry_tcbinfo
-- and an output type, i.e. struct pcbinfo *
--
function get_vnet_member(vnet, mbname, outtype)
	db = vnet:GetChildMemberWithName("vnet_data_base")
	mb = lldb.target:FindFirstGlobalVariable(mbname)
		:AddressOf()
--		:Cast(lldb.target:FindFirstType("uintptr_t"))
	addr = db:GetValueAsUnsigned() + mb:GetValueAsUnsigned()

	return lldb.frame:EvaluateExpression("(" .. outtype .. ")" .. addr)
end

function tcbinfo_from_vnet(vnet)
-- (struct inpcbinfo*)((((struct vnet *) vnet0 )->vnet_data_base) + (uintptr_t )&vnet_entry_tcbinfo)
	return get_vnet_member(vnet, "vnet_entry_tcbinfo", "struct inpcbinfo *")
end

function hexdump(bytes)
	i = 0	
	for b in string.gmatch(bytes, ".") do
		i = i + 1	
		io.write(string.format("%02X ", string.byte(b)))
		if i % 8  == 0 then
			io.write("  ")
		end
		if i % 16 == 0 then
			io.write("\n")
		end
	end
	io.write("\n")
end

-- The following variables are available in the interactive context
-- print(lldb.debugger)
-- print(lldb.target)
-- print(lldb.frame)
-- print(lldb.process)
-- print(lldb.thread)

vnet0 = lldb.target:FindFirstGlobalVariable("vnet0")

if vnet0 == nil
then
	print("couldn't find vnet0, this might not be a vimage kernel")
else
	print(vnet0)
	print("walking vnets")
	vnets = walk_vnets(vnet0)
	print("Found " .. #vnets .. " vnets")

	for i, vnet in pairs(vnets) do
		ti = tcbinfo_from_vnet(vnet)
		inplist = walk_inplist(ti:GetChildMemberWithName("ipi_listhead")
					 :GetChildMemberWithName("clh_first"))

		print("ti and first")
		print(ti)
		print(ti:GetChildMemberWithName("ipi_listhead")
		 	:GetChildMemberWithName("clh_first"))

		for i, inpcb in pairs(inplist) do
			tcpcb = inpcb:Cast(lldb.target:FindFirstType("struct tcpcb")
						    :GetPointerType())
			print(tcpcb)
			if tcpcb:GetChildMemberWithName("t_lognum")
				:GetValueAsSigned() ~= 0 then
				print("\t" ..	
					tcpcb:GetChildMemberWithName("t_lognum")
					     :GetValueAsSigned() ..
					" log entries")

				entry = tcpcb:GetChildMemberWithName("t_logs")
					     :GetChildMemberWithName("stqh_first")

				logbuf = ""
				while entry:GetValueAsSigned() ~= 0 do
					logbuf = logbuf .. tcplog_format_entry(entry)
					entry = entry:GetChildMemberWithName("tlm_queue")
						     :GetChildMemberWithName("stqe_next")
					print("\tlogbuf is " .. #logbuf .. " bytes")
				end

				hdr = tcplog_format_hdr(tcpcb, inpcb, #logbuf)
				print("hdr: " .. #hdr .. " logbuf: " .. #logbuf .. " (total " .. #hdr + #logbuf .. ")")
				print("logbuf is " .. #logbuf .. " bytes")

				filename = tcpcb:GetValue() .. "_tcp_log.bin"
				print("\tlog written to " .. filename)

				logfile = io.open(filename, "wb")
				logfile:write(hdr)
				logfile:write(logbuf)
				logfile:close()
			else
				print("\tno logs")
			end
		end
		
	end
end
