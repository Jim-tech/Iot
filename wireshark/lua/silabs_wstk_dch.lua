-- This is a simple script to decode the debug channel messages of the silabs WSTK.

-- PTI capturing protocol
pti_protocol = Proto("PTI",  "Silicon Labs PTI Capturing Protocol")

pti_hw_start        = ProtoField.uint8("pti.hw_start",        "hw_start",          base.HEX)
pti_packet          = ProtoField.bytes("pti.packet",          "pti_packet",        base.NONE)
pti_hw_end          = ProtoField.uint8("pti.hw_end",          "hw_end",            base.HEX)
pti_txrx            = ProtoField.uint8("pti.txrx",            "txrx",              base.DEC)
pti_rssi            = ProtoField.int8("pti.rssi",             "rssi",              base.DEC)
pti_channel         = ProtoField.uint8("pti.channel",         "channel",           base.DEC)
pti_phy             = ProtoField.uint8("pti.protocol",        "protocol",          base.DEC)

pti_protocol.fields = { pti_hw_start, pti_packet, pti_hw_end, pti_txrx, pti_rssi, pti_channel, pti_phy }

function pti_protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 
	then 
		return
	else
		if (length <= 5)
		then
			return
		end
	end


	local subtree = tree:add(pti_protocol, buffer(), "PTI Capture Data")
	
	subtree:add_le(pti_hw_start, buffer(0,1))
	
	-- check total append length and tx/rx
	local append_len = buffer:range(length-1,1):bitfield(2,3) + 3 -- AN1087 is not accurate
	local is_rx = buffer:range(length-1,1):bitfield(1,1)
	local error_code = buffer:range(length-2,1):bitfield(0,4)
	local protocol_id = buffer:range(length-2,1):bitfield(4,4)
	local hw_end_val = buffer:range(length-append_len-1,1):uint()
	if (hw_end_val ~= 0xF9 and hw_end_val ~= 0xFD)
	then
		return
	end
	
	pinfo.cols.protocol = pti_protocol.name
	
	local pti_phy_table = {
		[0] = "Custom",
		[1] = "EFR32 EmberPHY",
		[2] = "Thread on RAIL",
		[3] = "Bluetooth LE",
		[4] = "Connect on RAIL",
		[5] = "Zigbee on RAIL"
	}

	local channel = buffer:range(length-3,1):bitfield(2,6)
	
	if (5 == protocol_id)
	then
		frame_len = buffer:range(1,1):uint()
		Dissector.get("wpan"):call(buffer(2,frame_len):tvb(),pinfo,subtree)
	else
		if (3 == protocol_id)
		then
			if (39 == channel or 12 == channel or 0 == channel)
			then
				access_addr = ByteArray.new("D6BE898E")
			else
				access_addr = ByteArray.new("00000000")
			end
			
			local ble_pti_data = buffer(1,length-append_len-2):bytes()
			ble_pti_data:prepend(access_addr)
			local ble_tvb = ByteArray.tvb(ble_pti_data, "BLE Data")
			Dissector.get("btle"):call(ble_tvb,pinfo,subtree)
			-- Dissector.get("btle"):call(buffer(1,length-append_len-1):tvb(),pinfo,subtree)
		else
			subtree:add_le(pti_packet, buffer(1,length-append_len-1))
		end
	end

	subtree:add_le(pti_hw_end, hw_end_val)

	local pti_txrx_table = {
		[0] = "Tx",
		[1] = "Rx",
	}
	
	subtree:add_le(pti_txrx, is_rx, pti_txrx_table[is_rx].." ("..is_rx..")")
	if (is_rx ~= 0)
	then
		subtree:add_le(pti_rssi, 0-buffer:range(length-append_len,1):int())
	end
	
	-- channel 
	if (5 == protocol_id)
	then
		channel = channel + 11
	end
	subtree:add_le(pti_channel, channel)
	
	subtree:add_le(pti_phy, protocol_id, pti_phy_table[protocol_id].." ("..protocol_id..")")

end

-- WSTK debug channel protocol 
wstk_dch_protocol = Proto("WSTK",  "WSTK Debug Channel Protocol")

dch_version       = ProtoField.uint16("wstk.dch_version",      "dch_version",         base.DEC)
dch_timestamp     = ProtoField.uint64("wstk.dch_timestamp",    "dch_timestamp",       base.DEC)
dch_msg_type      = ProtoField.uint16("wstk.dch_msg_type",     "dch_msg_type",        base.DEC)
dch_data          = ProtoField.bytes("wstk.dch_data",          "dch_data",            base.NONE)
dch_seq_no        = ProtoField.uint8("wstk.dch_seq_no",        "dch_seq_no",          base.DEC)

wstk_dch_protocol.fields = { dch_version, dch_timestamp, dch_msg_type, dch_data, dch_seq_no }

local dch_msg_type_table = {
	[0] = "TimeSync",
	[1] = "Reset",
	[2] = "Printf",
	[3] = "APITrace",
	[4] = "Assert",
	[10] = "Sniffer Packet",
	[41] = "EFR32 Tx Packet",
	[42] = "EFR32 Rx Packet",
	[60] = "EZSP",
	[61] = "ASH"
}

function wstk_dch_protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 
	then 
		return 
	end

	pinfo.cols.protocol = wstk_dch_protocol.name

	local subtree = tree:add(wstk_dch_protocol, buffer(), "WSTK Debug Channel Data")

	
	local version_val = buffer:range(0,2):le_uint()
	if (2 == version_val)
	then
		subtree:add_le(dch_version, version_val)
		
		-- timestamp
		timestamp_val = buffer:range(2,6):le_uint64()
		subtree:add_le(dch_timestamp, timestamp_val)
		
		-- decode msgtype
		local msg_type_val = buffer:range(8,2):le_uint()
		if dch_msg_type_table[msg_type_val]
		then
			subtree:add_le(dch_msg_type, msg_type_val, dch_msg_type_table[msg_type_val].." ("..msg_type_val..")")
		else
			subtree:add_le(dch_msg_type, msg_type_val)
		end
		
		subtree:add_le(dch_seq_no, buffer(10,1))
		
		-- decode according to msg type
		if (10 == msg_type_val or 41 == msg_type_val or 42 == msg_type_val)
		then
			pti_protocol.dissector(buffer:range(11,-1):tvb(),pinfo,subtree)
		else
			subtree:add_le(dch_data, buffer(11,-1))
		end
		
	else
		-- version 1 and 3 unsupported yet
		subtree:add_le(dch_version, version_val)
		subtree:add_le(dch_data, buffer(2,-1))
	end
end
