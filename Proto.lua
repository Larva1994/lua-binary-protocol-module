local Proto = class("Proto")

function Proto:ctor(fclass, pts, bClient)
	self.compLen = 256
	if not pts then
		print("init packparse failed. pts or actions is nil.")
		return
	end
	self.cmd2act = {}
	for _, ptmod in pairs(pts) do
		local ptinfo = require(ptmod[1])
		self:AddProto(fclass, ptinfo, bClient)
	end
end

function Proto:CreateDynamicFunction(pack_proto, parse_proto)
	local fds = {
		boolean = {
			fmt = "<b", def = "and 1 or 0"
		},
		int8 = {
			fmt = "<b", def = "or 0"
		},
		uint8 = {
			fmt = "<B", def = "or 0"
		},
		int16 = {
			fmt = "<h", def = "or 0"
		},
		uint16 = {
			fmt = "<H", def = "or 0"
		},
		int32 = {
			fmt = "<i4", def = "or 0"
		},
		uint32 = {
			fmt = "<I4", def = "or 0"
		},
		number = {
			fmt = "<n", def = "or 0"
		},
		string = {
			fmt = "<z", def = "or \"\""
		},
		bytes = {
			fmt = "<s4", def = "or \"\""
		}
	}
	if not pack_proto and not parse_proto then return end
	
	local codeT, l_fd, l_fmt = {
		"return function(body)",
		"local bufT, insertT, packS = {}, table.insert, string.pack"
	}, {}, {}
	local function pack_nest(body, bodyname, dep)
		if not dep then dep = 1 end
		for _, field in pairs(body) do
			local fd = fds[field[1]]
			local fdname = string.format("%s[\"%s\"]", bodyname, field[2])
			if fd then
				table.insert(l_fd, fdname.." "..tostring(fd.def))
				table.insert(l_fmt, fd.fmt)
			elseif field[1] == "table" then
				pack_nest(field[3], fdname, dep + 1)
			elseif field[1] == "array" then
				if #l_fd > 0 then
					table.insert(codeT, string.format("insertT(bufT, packS(\"%s\", %s))", table.concat(l_fmt), table.concat(l_fd, ", ")))
					l_fd, l_fmt = {}, {}
				end
				table.insert(codeT, string.format("local arr%d = %s or {}", dep, fdname))
				table.insert(codeT, string.format("insertT(bufT, packS(\"I4\", #arr%d))", dep))
				table.insert(codeT, string.format("for i%d = 1, #arr%d do", dep, dep))
				fd = fds[field[3]]
				if fd then
					table.insert(l_fd, string.format("arr%d[i%d] %s", dep, dep, tostring(fd.def)))
					table.insert(l_fmt, fd.fmt)
				else
					pack_nest(field[3], string.format("arr%d[i%d]", dep, dep), dep + 1)
				end
				if #l_fd > 0 then
					table.insert(codeT, string.format("insertT(bufT, packS(\"%s\", %s))", table.concat(l_fmt), table.concat(l_fd, ", ")))
					l_fd, l_fmt = {}, {}
				end
				table.insert(codeT, "end")
			end
		end
		if #l_fd > 0 then
			table.insert(codeT, string.format("insertT(bufT, packS(\"%s\", %s))", table.concat(l_fmt), table.concat(l_fd, ", ")))
			l_fd, l_fmt = {}, {}
		end
	end
	pack_nest(pack_proto, "body")
	table.insert(codeT, "return table.concat(bufT)")
	table.insert(codeT, "end")
	local packcodes = table.concat(codeT, "\n")
	--print(packcodes)

	local codeT, l_fd, l_fmt = {
		"return function(buf, pos_read)",
		"local body, val, unpackS = nil, nil, string.unpack"
	}, {}, {}
	local function parse_nest(body, bodyname, dep)
		if not dep then dep = 1 end
		table.insert(codeT, string.format("local body%d = {}", dep))
		table.insert(codeT, string.format("%s = body%d", bodyname, dep))
		bodyname = string.format("body%d", dep)
		for _, field in pairs(body) do
			local fd = fds[field[1]]
			local fdname = string.format("%s[\"%s\"]", bodyname, field[2])
			if fd then
				table.insert(l_fd, fdname)
				table.insert(l_fmt, fd.fmt)
			else
				if field[1] == "table" then
					parse_nest(field[3], fdname, dep + 1)
				elseif field[1] == "array" then
					if #l_fd > 0 then
						table.insert(l_fd, "pos_read")
						table.insert(codeT, string.format("%s = unpackS(\"%s\", buf, pos_read)", table.concat(l_fd, ", "), table.concat(l_fmt)))
						l_fd, l_fmt = {}, {}
					end
					table.insert(codeT, string.format("local arr%d, arrNum%d = {}, 0", dep, dep))
					table.insert(codeT, string.format("%s = arr%d", fdname, dep))
					table.insert(codeT, string.format("arrNum%d, pos_read = unpackS(\"<I4\", buf, pos_read)", dep))
					table.insert(codeT, string.format("for i%d = 1, arrNum%d do", dep, dep))
					fd = fds[field[3]]
					if fd then
						table.insert(l_fd, string.format("arr%d[i%d]", dep, dep))
						table.insert(l_fmt, fd.fmt)
					else
						parse_nest(field[3], string.format("arr%d[i%d]", dep, dep), dep + 1)
					end
					if #l_fd > 0 then
						table.insert(l_fd, "pos_read")
						table.insert(codeT, string.format("%s = unpackS(\"%s\", buf, pos_read)", table.concat(l_fd, ", "), table.concat(l_fmt)))
						l_fd, l_fmt = {}, {}
					end
					table.insert(codeT, "end")
				end
			end
		end
		if #l_fd > 0 then
			table.insert(l_fd, "pos_read")
			table.insert(codeT, string.format("%s = unpackS(\"%s\", buf, pos_read)", table.concat(l_fd, ", "), table.concat(l_fmt)))
			l_fd, l_fmt = {}, {}
		end
	end
	parse_nest(parse_proto, "body")
	table.insert(codeT, "return body")
	table.insert(codeT, "end")
	local parsecodes = table.concat(codeT, "\n")
	--print(parsecodes)

	return load(packcodes)(), load(parsecodes)()
end

function Proto:AddProto(fclass, protos, bClient)
	if not protos then return end
	for name, proto in pairs(protos) do
		local t, cmd = {}, proto.SUBCMD
		_G[name] = cmd
		if fclass then
			fclass.actions[cmd] = fclass["on"..name]
		end
		if bClient then
			t.pack, t.parse = self:CreateDynamicFunction(proto.BODY.C, proto.BODY.S)
		else
			t.pack, t.parse = self:CreateDynamicFunction(proto.BODY.S, proto.BODY.C)
		end
		self.cmd2act[cmd] = t
	end
end

function Proto:Pack(cmd, data)
	if not cmd or not data then
		return
	end
	local packfunc = self.cmd2act[cmd]
	if not packfunc then
		print("error! pack undefined cmd "..tostring(cmd))
		return
	end
	local buf = packfunc.pack(data)
	local orglen = #buf
	packfunc = self.cmd2act[HEADER]
	if orglen > self.compLen then
		buf = btCompress.Encode_Lz4(buf)
	end
	return packfunc.pack({
		cmd = cmd,
		crypt = {
			type = 0
		},
		compress = {
			type = orglen > self.compLen and 1 or 0,
			len = orglen
		},
		verify = {
			type = 0,
			token = ""
		},
		data = buf
	})
end

function Proto:Parse(pack)
	if not pack or #pack < 4 then
		return
	end
	local packfunc = self.cmd2act[HEADER]
	local header = packfunc.parse(pack)
	local buf = header.data
	if header.compress.type == 1 then
		buf = btCompress.Decode_Lz4(header.data, header.compress.len)
	end
	parsefunc = self.cmd2act[header.cmd]
	if not parsefunc then
		print("error! parse undefined cmd "..tostring(header.cmd))
		return
	end
	return header.cmd, parsefunc.parse(buf)
end

return Proto