--[[
Example Protos File:

local Header = {
	{"uint16",	"MsgId"},
	{"uint8",	"CompressType"},
	{"uint8",	"CryptType"},
	{"uint32",	"UncompressSize"},
	{"uint32",	"CheckSum"},
}
return {
	HEADER = {
		SUBCMD = 0,
		BODY = {
			CS = Header,
			SC = {},
		}
	},
	DEBUG = {
		SUBCMD = 99,
		BODY = {
			CS = {
				{"table",	"header",	Header},
				{"string",	"str"},
			},
			SC = {}
		}
	}
}

]]

local Proto
if class then
	Proto = class("Proto")
	function Proto:ctor(pts)
		self.fmt = {
			boolean = {
				fmt = "<b", def = false
			},
			int8 = {
				fmt = "<b", def = 0
			},
			uint8 = {
				fmt = "<B", def = 0
			},
			int16 = {
				fmt = "<h", def = 0
			},
			uint16 = {
				fmt = "<H", def = 0
			},
			int32 = {
				fmt = "<i4", def = 0
			},
			uint32 = {
				fmt = "<I4", def = 0
			},
			number = {
				fmt = "<n", def = 0
			},
			string = {
				fmt = "<z", def = "\"\""
			},
			data = {
				fmt = "<s4", def = "\"\""
			},
		}
		self.name2act = {}
		self.cmd2act = {}

		self.tmp_fmt = {}
		self.tmp_val = {}

		for _, ptmod in pairs(pts) do
			self:AddProto(require(ptmod))
		end
	end
else
	Proto = {
		fmt = {
			boolean = {
				fmt = "<b", def = false
			},
			int8 = {
				fmt = "<b", def = 0
			},
			uint8 = {
				fmt = "<B", def = 0
			},
			int16 = {
				fmt = "<h", def = 0
			},
			uint16 = {
				fmt = "<H", def = 0
			},
			int32 = {
				fmt = "<i4", def = 0
			},
			uint32 = {
				fmt = "<I4", def = 0
			},
			number = {
				fmt = "<n", def = 0
			},
			string = {
				fmt = "<z", def = "\"\""
			},
			data = {
				fmt = "<s4", def = "\"\""
			},
		},
		name2act = {},
		cmd2act = {},

		tmp_fmt = {},
		tmp_val = {},
	}
	function Proto:ImportProtos(pts)
		for _, ptmod in pairs(pts) do
			self:AddProto(require(ptmod))
		end
	end
end

-- 拼接字符串时使用table.concat更好

-- 解析协议并产生专用序列化代码
function Proto:DynamicPackCode(outCodes, t, tname)
	local function flushTmp()
		if #self.tmp_fmt > 0 then
			table.insert(outCodes, string.format("insert(buf, pack(\"%s\", %s))", table.concat(self.tmp_fmt), table.concat(self.tmp_val, ", ")))
			self.tmp_fmt = {}
			self.tmp_val = {}
		end
	end
	for _, field in pairs(t) do
		local field_type = field[1]
		local field_name = string.format("%s[\"%s\"]", tname, field[2])
		local field_format = self.fmt[field_type]

		if field_format then
			-- 简单格式
			table.insert(self.tmp_fmt, field_format.fmt)
			table.insert(self.tmp_val, field_name.." or "..tostring(field_format.def))
		else
			-- 复杂格式
			if field_type == "bytes" then
				-- 固定长度字节数组
				local field_len = field[3]
				table.insert(self.tmp_fmt, string.format("<c%d", field_len))
				table.insert(self.tmp_val, field_name.." or \"\"")
			elseif field_type == "table" then
				-- 表
				local field_table = field[3]
				local tmp_table_name = string.format("%s_%s", tname, field[2])

				table.insert(outCodes, string.format("local %s = %s or {}", tmp_table_name, field_name))
				self:DynamicPackCode(outCodes, field_table, tmp_table_name)
			elseif field_type == "array" then
				flushTmp()
				local array_type = field[3]
				local tmp_array_name = string.format("%s_%s", tname, field[2])
				local tmp_array_v_name = string.format("%s_v", tmp_array_name)

				table.insert(outCodes, string.format("local %s = %s or {}", tmp_array_name, field_name))
				table.insert(outCodes, string.format("insert(buf, pack(\"<I4\", #%s))", tmp_array_name))
				table.insert(outCodes, string.format("for %s_k, %s_v in ipairs(%s) do", tmp_array_name, tmp_array_name, tmp_array_name))

				if type(array_type) == "string" then
					field_format = self.fmt[array_type]
					if field_format then
						table.insert(self.tmp_fmt, field_format.fmt)
						table.insert(self.tmp_val, tmp_array_v_name.." or "..tostring(field_format.def))
					elseif array_type == "bytes" then
						local field_len = field[4]
						table.insert(self.tmp_fmt, string.format("<c%d", field_len))
						table.insert(self.tmp_val, tmp_array_v_name.." or \"\"")
					end
				elseif type(array_type) == "table" then
					local field_table = field[3]
					local tmp_table_name = string.format("%s_t", tmp_array_v_name)
					table.insert(outCodes, string.format("local %s = %s or {}", tmp_table_name, tmp_array_v_name))
					self:DynamicPackCode(outCodes, field_table, tmp_table_name)
				end
				flushTmp()
				table.insert(outCodes, "end")
			end
		end
	end
	flushTmp()
end

-- 解析协议并产生专用反序列化代码
function Proto:DynamicParseCode(outCodes, t, tname)
	local function flushTmp()
		if #self.tmp_fmt > 0 then
			table.insert(outCodes, string.format("%s, pos = unpack(\"%s\", buf, pos)", table.concat(self.tmp_val, ", "), table.concat(self.tmp_fmt)))
			self.tmp_fmt = {}
			self.tmp_val = {}
		end
	end
	for _, field in pairs(t) do
		local field_type = field[1]
		local field_name = string.format("%s[\"%s\"]", tname, field[2])
		local field_format = self.fmt[field_type]

		if field_format then
			-- 简单格式
			table.insert(self.tmp_fmt, field_format.fmt)
			table.insert(self.tmp_val, field_name)
		else
			-- 复杂格式
			if field_type == "bytes" then
				-- 固定长度字节数组
				local field_len = field[3]
				table.insert(self.tmp_fmt, string.format("<c%d", field_len))
				table.insert(self.tmp_val, field_name)
			elseif field_type == "table" then
				-- 表
				local field_table = field[3]
				local tmp_table_name = string.format("%s_%s", tname, field[2])

				table.insert(outCodes, string.format("local %s = {}", tmp_table_name))
				self:DynamicParseCode(outCodes, field_table, tmp_table_name)
				table.insert(outCodes, string.format("%s = %s", field_name, tmp_table_name))
			elseif field_type == "array" then
				flushTmp()
				local array_type = field[3]
				local tmp_array_name = string.format("%s_%s", tname, field[2])
				local tmp_array_v_name = string.format("%s[%s_i]", tmp_array_name, tmp_array_name)

				table.insert(outCodes, string.format("local %s = {}", tmp_array_name))
				table.insert(outCodes, string.format("local %s_len, pos = unpack(\"<I4\", pos)", tmp_array_name))
				table.insert(outCodes, string.format("for %s_i = 1, %s_len do", tmp_array_name, tmp_array_name))

				if type(array_type) == "string" then
					field_format = self.fmt[array_type]
					if field_format then
						table.insert(self.tmp_fmt, field_format.fmt)
						table.insert(self.tmp_val, tmp_array_v_name)
					elseif array_type == "bytes" then
						local field_len = field[4]
						table.insert(self.tmp_fmt, string.format("<c%d", field_len))
						table.insert(self.tmp_val, tmp_array_v_name)
					end
				elseif type(array_type) == "table" then
					local field_table = field[3]
					local tmp_table_name = string.format("%s_t", tmp_array_v_name)

					table.insert(outCodes, string.format("local %s = {}", tmp_table_name))
					self:DynamicParseCode(outCodes, field_table, tmp_table_name)
					table.insert(outCodes, string.format("%s = %s", tmp_array_v_name, tmp_table_name))
				end
				flushTmp()
				table.insert(outCodes, "end")
				table.insert(outCodes, string.format("%s = %s", field_name, tmp_array_name))
			end
		end
	end
	flushTmp()
end

function Proto:CreatePackFunction(proto)
	if not proto then return end
	local pack_codes = {
		"return function(body)",
		"local buf = {}",
		"local insert, pack, concat = table.insert, string.pack, table.concat"
	}
	self:DynamicPackCode(pack_codes, proto, "body")
	table.insert(pack_codes, "return concat(buf)")
	table.insert(pack_codes, "end")
	return load(table.concat(pack_codes, "\n"))()
end

function Proto:CreateParseFunction(proto)
	if not proto then return end
	local parse_codes = {
		"return function(buf, pos)",
		"local body = {}",
		"local unpack = string.unpack"
	}
	self:DynamicParseCode(parse_codes, proto, "body")
	table.insert(parse_codes, "return body")
	table.insert(parse_codes, "end")
	return load(table.concat(parse_codes, "\n"))()
end

function Proto:AddProto(proto)
	for name, info in pairs(proto) do
		local cmd = info.SUBCMD
		local t = {
			pack = self:CreatePackFunction(info.BODY.SC),
			parse = self:CreateParseFunction(info.BODY.CS)
		}
		self.name2act[name] = t
		self.cmd2act[cmd] = t
	end
end

function Proto:Pack(cmd, body)
	local func = self.cmd2act[cmd] or self.name2act[cmd]
	if not func then
		print("error! undefined cmd "..tostring(cmd))
		return
	end
	return func.pack(body)
end

function Proto:Parse(cmd, buf)
	local func = self.cmd2act[cmd] or self.name2act[cmd]
	if not func then
		print("error! undefined cmd "..tostring(cmd))
		return
	end
	return func.parse(buf)
end

return Proto
