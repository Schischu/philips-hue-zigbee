-- info
print("hue postdissector loaded")

-- we need these fields from the gtp packets
zcl_cmd_id = Field.new("zbee_zcl.cs.cmd.id")
zcl_cmd_data = Field.new("data.data")

-- declare our postdissector
zcl_hue_pd = Proto("zcl_hue","Hue")

-- our fields
zcl_hue_ent_seqno = ProtoField.uint16("zcl_hue.seqno","Sequence Number", base.DEC)
zcl_hue_ent_len   = ProtoField.uint16("zcl_hue.len","Length", base.DEC)
zcl_hue_ent_res   = ProtoField.uint32("zcl_hue.res","Reserved", base.DEC)
zcl_hue_ent_type  = ProtoField.uint16("zcl_hue.type","Type", base.DEC_HEX )
zcl_hue_ent_elem  = ProtoField.uint16("zcl_hue.elem","Elements", base.DEC)
zcl_hue_ent_dst   = ProtoField.uint16("zcl_hue.dst","Destination", base.HEX)

zcl_hue_ent_b     = ProtoField.uint16("zcl_hue.b","B", base.DEC_HEX )
zcl_hue_ent_x     = ProtoField.uint16("zcl_hue.x","X", base.DEC_HEX )
zcl_hue_ent_y     = ProtoField.uint16("zcl_hue.y","Y", base.DEC_HEX )
zcl_hue_ent_xf     = ProtoField.float("zcl_hue.xf","XF")
zcl_hue_ent_yf     = ProtoField.float("zcl_hue.yf","YF")
zcl_hue_ent_response  = ProtoField.string("zcl_hue.response","Response")
zcl_hue_ent_response_xor  = ProtoField.string("zcl_hue.response_xor","Response Xor")

zcl_hue_switch_keycode = ProtoField.uint8("zcl_hue.keycode","Keycode", base.DEC)
zcl_hue_switch_keystate = ProtoField.uint8("zcl_hue.keystate","Keystate", base.DEC)
zcl_hue_switch_keyhold = ProtoField.uint8("zcl_hue.keyhold","Keyhold Time", base.DEC)

zcl_hue_switch_unk1 = ProtoField.uint8("zcl_hue.unk1","Unk1", base.DEC_HEX)
zcl_hue_switch_unk3 = ProtoField.uint8("zcl_hue.unk3","Unk3", base.DEC_HEX)
zcl_hue_switch_unk5 = ProtoField.uint8("zcl_hue.unk5","Unk5", base.DEC_HEX)

zcl_hue_pd.fields = {
	zcl_hue_ent_seqno, 
	zcl_hue_ent_len, 
	zcl_hue_ent_res, 
	zcl_hue_ent_type, 
	zcl_hue_ent_elem, 
	zcl_hue_ent_dst, 
	zcl_hue_ent_response, 
	zcl_hue_ent_response_xor, 
	zcl_hue_ent_x, 
	zcl_hue_ent_xf, 
	zcl_hue_ent_y, 
	zcl_hue_ent_yf, 
	zcl_hue_ent_b, 
	zcl_hue_switch_keycode, 
	zcl_hue_switch_keystate, 
	zcl_hue_switch_keyhold, 
	zcl_hue_switch_unk1, 
	zcl_hue_switch_unk3, 
	zcl_hue_switch_unk5
}

-- dissect each packet
function zcl_hue_pd.dissector(buffer,pinfo,tree)
  length = buffer:len()
  if length == 0 then return end

  local zclcmdid  = zcl_cmd_id()
  if not zclcmdid then return end

  -- print("zclcmdid: " .. tostring(zclcmdid))

  if zclcmdid() == 0 then
    pinfo.cols.protocol = zcl_hue_pd.name

    local info = "Switch: "

    local zclcmddata = zcl_cmd_data()

    local zclcmdtvb = ByteArray.tvb(zclcmddata(), "ZigBee Hue Payload")
    local subtree = tree:add(zcl_hue_pd, "Zigbee Hue")



	-- Short Key1
	-- 01 0000 30 00 21 0000
	-- 01 0000 30 02 21 0100
	-- 01 0000 30 02 21 0100
	
	-- Long Key1
	-- 01 0000 30 00 21 0000
	-- 01 0000 30 01 21 0800
	-- 01 0000 30 01 21 1000
	-- 01 0000 30 01 21 1800
	-- 01 0000 30 03 21 1d00
    local keycode  = zclcmdtvb:range(0, 1):le_uint()
    local unk1     = zclcmdtvb:range(1, 2):le_uint()
    local unk3     = zclcmdtvb:range(3, 1):le_uint()
    local keystate = zclcmdtvb:range(4, 1):le_uint()
    local unk5     = zclcmdtvb:range(5, 1):le_uint()
    local keyhold  = zclcmdtvb:range(6, 2):le_uint()
	
	local keystate_str = ""
	
	if keystate == 0 then
		keystate_str = "DOWN"
	elseif keystate == 1 then
		keystate_str = "HOLD"
	elseif keystate == 2 then
		keystate_str = "RELEASE_SHORT"
	elseif keystate == 3 then
		keystate_str = "RELEASE_LONG"
	end
	
	info = info .. string.format("Key %u: %u(%s) %u", keycode, keystate, keystate_str, keyhold) .. " "
	
    subtree:add_le(zcl_hue_switch_keycode, keycode)
    subtree:add_le(zcl_hue_switch_keystate, keystate)
    subtree:add_le(zcl_hue_switch_keyhold, keyhold)
    subtree:add_le(zcl_hue_switch_unk1, unk1)
    subtree:add_le(zcl_hue_switch_unk3, unk3)
    subtree:add_le(zcl_hue_switch_unk5, unk5)

    pinfo.cols.info:set(info)
  end
  
  if zclcmdid() == 1 or zclcmdid() == 2 then
    pinfo.cols.protocol = zcl_hue_pd.name

    local info = "Hue Entertainment "
    if zclcmdid() == 1 then
      info = info .. "Request  "
    else
      info = info .. "Response "
    end

    local zclcmddata = zcl_cmd_data()

    local zclcmdtvb = ByteArray.tvb(zclcmddata(), "ZigBee Hue Payload")
    local subtree = tree:add(zcl_hue_pd, "Zigbee Hue")

    local seqno = zclcmdtvb:range(0, 2):le_uint()
    local res   = zclcmdtvb:range(2,3):le_uint()
    local ltype = zclcmdtvb:range(5,1):le_uint()

    subtree:add_le(zcl_hue_ent_seqno, seqno)
    subtree:add_le(zcl_hue_ent_len, zclcmdtvb:len())
    subtree:add_le(zcl_hue_ent_res, res)
    subtree:add_le(zcl_hue_ent_type, ltype)

    --print("zclcmdtvb.len: " .. tostring(zclcmdtvb:len()))
    local elements = math.floor((zclcmdtvb:len() - 6) / 7)

    subtree:add_le(zcl_hue_ent_elem, elements)

    local offset = 6

    local i = 0
    while i < elements do
	    local dst   = zclcmdtvb:range(offset,2):le_uint()

	    -- X                                    32 10          BA987654
	    -- Y                        7654321 0         BA 9 8           
	    -- B 210         A9876543                                       

	    local b = bit.band(zclcmdtvb:range(offset+2,2):le_uint(), 0xFFE0)
	    -- local b = bit.rshift(zclcmdtvb:range(8,2):le_uint(), 5)

	    local x = bit.band(zclcmdtvb:range(offset+4,2):le_uint(), 0x0FFF)
	    x = bit.lshift(x, 4)
	    local y = bit.band(zclcmdtvb:range(offset+5,2):le_uint(), 0xFFF0)

	    local yf = (y * 1.0) / 65536.0
	    local xf = (x * 1.0) / 65536.0


	    info = info .. string.format("%u: 0x%04x", i, dst) .. " "

	    subtree:add_le(zcl_hue_ent_dst, dst)
	    subtree:add_le(zcl_hue_ent_x, x)
	    subtree:add_le(zcl_hue_ent_y, y)
	    subtree:add_le(zcl_hue_ent_b, b)
	    subtree:add(zcl_hue_ent_xf, xf)
	    subtree:add(zcl_hue_ent_yf, yf)

	    offset = offset + 7
	    i = i + 1
	  end

    pinfo.cols.info:set(info)

    if zclcmdid() == 2 then
    	local response  = zclcmdtvb:range(offset)
    	local responseXor = zclcmdtvb:bytes(offset)
    		--print("responseXor.len: " .. tostring(responseXor:len()))
    	for i=0, responseXor:len() - 1 do
    		--print("responseXor.i: " .. tostring(i))
    		responseXor:set_index(i, bit.bxor(responseXor:get_index(i), 0xFF))
    	end
      subtree:add(zcl_hue_ent_response, tostring(response))
      subtree:add(zcl_hue_ent_response_xor, tostring(responseXor))
    end
  end
end -- end dissector function

-- register ourselfs
register_postdissector(zcl_hue_pd)

-- local zcl_cmd_id = DissectorTable.get("zbee_zcl.cs.cmd.id")
-- zcl_cmd_id:add(1, zcl_hue_pd)



