
/**
 * Because strings need a function that'll trim whitespace
 */
String.prototype.trim = function () {
    return this.replace(/^\s*/, "").replace(/\s*$/, "");
}

function color_hex_field(px, node)
{
	var hexstart = node.getAttribute("hexstart");
	if (hexstart == undefined)
		return;
	var start = parseInt(hexstart);

	var hexstop = node.getAttribute("hexstop");
	if (hexstop == undefined)
		return;
	var stop = parseInt(hexstop);
	if (stop == 0)
		return;

	var hexindex = document.getElementById("hexindex");
	hexindex.innerHTML = dump_hex_index(px,start,stop);

	var hexbytes = document.getElementById("hexbytes");
	hexbytes.innerHTML = dump_hex_bytes(px,start,stop);

	var hexdatachars = document.getElementById("hexdatachars");
	hexdatachars.innerHTML = dump_hex_datachars(px,start,stop);
}


function do_shade_hex(node)
{
	if (fieldname) {
		var line = node.firstChild.innerHTML;
		var colon = line.indexOf(':');
		if (colon >= 0) {
			var name = line.substring(0, colon);
			var value = line.substring(colon+1).trim();

			fieldname.innerHTML = name;

			var fieldvalue = document.getElementById("fieldvalue");
			fieldvalue.value = value;
		}
	}
	color_hex_field(pxhex,node);
}

var pxhex;

var packets = [];
var packettimes = [];
var linktype = 0;
var fieldname;

function decode_packet(px)
{
	if (!px)
		return;

	fieldname = document.getElementById("fieldname");

	/* Save off a pointer to the data */
	pxhex = px;

	/* Find the "details" and "hex" fields within the HTML document
	 * where we are going to place the decoded contents */
	try {
		details = document.getElementById("details");
	} catch (er) {
		alert(er);
		return;
	}

	/* Remove the existing content in the "details" pane */
	details.innerHTML = "";

	/* Create the root of the tree structure */
	domtree = document.createElement("ul");
	domtree.id = "domtree";
	details.appendChild(domtree);

	/* Decode the packet */
	decode_wifi(domtree, px);

	var start = px.length;
	var stop = px.length;

	var hexindex = document.getElementById("hexindex");
	hexindex.innerHTML = dump_hex_index(px,start,stop);

	var hexbytes = document.getElementById("hexbytes");
	hexbytes.innerHTML = dump_hex_bytes(px,start,stop);

	var hexdatachars = document.getElementById("hexdatachars");
	hexdatachars.innerHTML = dump_hex_datachars(px,start,stop);
}


/**
 * Called from the HTML webpage to decode the hexdumps of packets
 * within the page.
 */
function run_decode()
{
	var hexbytes;
	var details;
	var px;

	/*
	 * First, let's parse the hexdumps into packets and remove them from
	 * the display. They should be in a structure that looks like:
	 * <div id=packetlist>
	 *  <div id=packetbytes>
	 *   01 02 03 04 05 06 ...
	 *  </div>
	 *  <div id=packetbytes>
	 *   aa e0 59 03 f1  ...
	 *  </div>
	 * </div>
	 */
	try {
		var list = document.getElementById("packetlist");
		var list2 = list.getElementsByTagName("div");
		var i;

		for (i=0; i<list2.length; i++) {
			packets[i] = hex_to_binary(list2[i].innerHTML);
			packettimes[i] = new Date(Date.parse(list2[i].getAttribute("timestamp")));
			linktype = list2[i].getAttribute("linktype");
		}

		list.innerHTML = "";
	} catch (er) {
		alert("run_decode(1) " + er);
	}

	/*
	 * DETAIL
	 * 
	 * Do a detailed decode of the first packet
	 */
	decode_packet(packets[0]);

	/*
	 * SUMMARY
	 *
	 * Do different things, depending on whether we have multiple
	 * packets or a single packet to decode.
	 */
	var summary = document.getElementById("summary");
	summary.innerHTML = '<table id="summarytable" width="100%"><tbody><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th></tr></tbody></table>';
	var x = document.getElementById("summarytable");
	if (packets.length) {
		var i;
		for (i=0; i<packets.length; i++)
			decode_packet_summary(x,packettimes[i],packets[i], i);
		x.rows[1].className = "selected";
	} else {
		var d = new Date();
		d.setTime(timestamp*1000 + microseconds/1000);
		decode_packet_summary(x,d,px,1);
	}
}


/**
 * Called when the user clicks on a packet in the summary.
 * We need to change the visual selection in the summary display,
 * then we need to change the DETAIL and HEX decodes to match
 * the selected packet
 */
function select_summary_packet(index)
{
	var summarytable = document.getElementById("summarytable");
	var i;

	/* Change the visual selection highlight */
	for (i=0; i<summarytable.rows.length; i++) {
		var row = summarytable.rows[i];
		if (i == index)
			row.className = "selected";
		else
			row.className = "unselected";
	}

	/* Change the packet details decode */
	decode_packet(packets[index-1]);
}

function dump_hex_index(px, start, stop)
{
	var result = "";
	var i;

	i=0;
	while (i < px.length) {
		result = result + hex16(i) + "<br/>\n";
		i += 16;
	}

	return result;
}

function dump_hex_bytes(px, start, stop)
{
	var result = "";
	var i;
	var hexshaded = false;

	for (i=0; i<px.length; i++) {
	    if (i==start) {
			result = result + '<b class=\"hexshade\">';
			hexshaded = true;
		}
		result = result + hex8(px[i]);
		if (i>=(stop-1) && hexshaded) {
			result = result + "</b>";
			hexshaded = false;
		}
		result = result + " ";
		if ((i%16) == 7)
		    result = result + "&nbsp;";
		if ((i%16) == 15) {
			if (hexshaded) {
				result = result + "</b>";
				hexshaded = false;
			}
			result = result + "<br/>\n";

			if (start <= i && i <= stop) {
				result = result + '<b class=\"hexshade\">';
				hexshaded = true;
			}
		}
	}

	if (hexshaded) {
		result = result + "</b>";
		hexshaded = false;
	}
	return result;
}

/**
 * When building a standard hex viewer [offset|hex|chars], this function
 * returns the characters. These will be either printable characters, or
 * a '.' dot character to represent non-printable data.
 */
function hexdatachar(c)
{

	if (32 <= c && c < 127) {
		var c2 = String.fromCharCode(c);
		if (c2 == '<')
			c2 = "&lt;";
		else if (c2 == '>')
			c2 = "&gt;";
		else if (c2 == '&')
			c2 = "&amp;";
		return c2;
	} else
		return '.';
}
function dump_hex_datachars(px, start, stop)
{
	var result = "";
	var i;
	var hexshaded = false;

	for (i=0; i<px.length; i++) {
	    if (i==start) {
			result = result + '<b class=\"hexshade\">';
			hexshaded = true;
		}
		result = result + hexdatachar(px[i]);
		if (i>=(stop-1) && hexshaded) {
			result = result + "</b>";
			hexshaded = false;
		}
		if ((i%16) == 7)
		    result = result + " ";
		if ((i%16) == 15) {
			if (hexshaded) {
				result = result + "</b>";
				hexshaded = false;
			}
			result = result + "<br/>\n";

			if (start <= i && i <= stop) {
				result = result + '<b class=\"hexshade\">';
				hexshaded = true;
			}
		}
	}

	if (hexshaded) {
		result = result + "</b>";
		hexshaded = false;
	}
	return result;
}

function add_summary_field(row, text)
{
	var div;
	var cell;

	div = document.createElement("div");
	div.setAttribute("onclick", "select_summary_packet(this.parentNode.parentNode.rowIndex)");
	div.innerHTML = text;

	cell = document.createElement("td");
	cell.appendChild(div);
	row.appendChild(cell);
	return cell;
}

function translate_mac_address(mac)
{
	if (macnames) {
		if (macnames[mac])
			return macnames[mac];
		else
			return mac;
	} else
		return mac;
}

function decode_packet_summary(summarytable, d, px, packet_number)
{
	var row = summarytable.insertRow(packet_number+1);
	var cell;
	
	cell = row.insertCell(0);
	cell.innerHTML = packet_number+1;
	cell.className = "number";

	add_summary_field(row, d.toLocaleTimeString());


	if (px.length > 1)
	switch (px[0]) {
	case 0x00:
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,10)));
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,4)));
		add_summary_field(row, "IEEE 802.11");
		cell = add_summary_field(row, "Association Request");
		break;
	case 0x10:
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,10)));
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,4)));
		add_summary_field(row, "IEEE 802.11");
		cell = add_summary_field(row, "Association Response");
		break;
	case 0x30:
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,10)));
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,4)));
		add_summary_field(row, "IEEE 802.11");
		cell = add_summary_field(row, "Reassociation Response");
		break;
	case 0x80:
	case 0x50:
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,10)));
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,4)));
		add_summary_field(row, "IEEE 802.11");
		if (px[0] == 0x80)
			cell = add_summary_field(row, "Beacon");
		else
			cell = add_summary_field(row, "Probe Response");
		cell.className = "description";
		break;
	case 0xb0:
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,10)));
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,4)));
		add_summary_field(row, "IEEE 802.11");
		cell = add_summary_field(row, "Authentication");
		break;
	case 0xc0:
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,10)));
		add_summary_field(row, translate_mac_address(macaddr_to_hex(px,4)));
		add_summary_field(row, "IEEE 802.11");
		cell = add_summary_field(row, "Deauthentication");
		break;
	}
}

function SELECT(num, array)
{
	if (array.length >= num)
		return "unknown";
	else
		return array[num];
}

function Range(start,stop,px)
{
    this.start = start;
    this.stop = stop;
    this.px = px;
    this.len = function() { return this.stop - this.start; }
    this.byteAt = function(offset) { return this.px[this.start + offset]; }
    this.sub = function(offset,length) {
        var result = new Range(this.start, this.stop, this.px);
        if (offset)
            result.start += offset;
        if (length)
            result.stop = result.start + length;
        return result;
    }
    this.slice = function(begin,end) { if (!begin) return this.px.slice(this.start, this.stop);}
    this.toDisplayString = function() {return display_string(this.slice());}
    this.DECIMAL_LE = function(node, text) {
        if (this.start > this.start)
            return 0;
        if (!this.px) {
            DECODEITEM(node, text + ": (err}");
            return 0;
        }
        var value = 0;
        for (var i=0; i<(this.stop-this.start); i++) {
            var val = 0 + this.px[this.start + i];
            value = value + (val << (i * 8));
        }

        DECODEITEM(node, text + ": " + value, this);
        return value;
    }
	return this;
}
                                                             
function decode_atheros_advanced_capability(node, field)
{
    if (field.len() < 1)
        return;
    
    
    var subtype = field.sub(0,1).DECIMAL_LE(node, "Subtype");
    if (subtype != 1)
		return;

	field.sub(1,1).DECIMAL_LE(node, "Version");
	
}

function decode_wifi_framecontrol(node, px)
{
	var field = new Range(0, px.length, px);
	var types = new Array("Management frame", "Control frame", "Data frame", "Data frame");
	var dsstatuss = new Array(
		"Not leaving DS or network is operating in AD-HOC mode (To DS: 0 From DS: 0) (0x00)",
		"unknown",
		"unknown",
		"unknown"
		);
	framecontrol = DECODETREE(node, "Frame control: " + NUMHEX16LE(px,0), field.sub(0,2));
	toggle(framecontrol.parentNode);
	
	version = px[0]&3;
	type = (px[0]>>2)&3;
	subtype = (px[0]>>4)&0xf;
	flags = px[1];
	ds = flags&3;

	DECODEITEM(framecontrol, "Version: " + version, field.sub(0,1));
	DECODEITEM(framecontrol, "Type: " + types[type] + "(" + type + ")", field.sub(0,1));
	DECODEITEM(framecontrol, "Subtype: " + subtype, field.sub(0,1));
	f = DECODETREE(framecontrol, "Flags: " + NUMHEX8(px,1), field.sub(1,2));
	toggle(f.parentNode);
	DECODEITEM(f, "DS status: " + dsstatuss[ds]);
	DECODEFLAG1(f, flags, 0x04, "More fragments", "This is the last fragment", "More fragments follow");
	DECODEFLAG1(f, flags, 0x08, "Retry", "Frame is not being retransmitted", "Frame is being retransmitted");
	DECODEFLAG1(f, flags, 0x10, "PWR MGMT", "STA will stay up", "STA will go to sleep");
	DECODEFLAG1(f, flags, 0x20, "More Data", "No data buffered", "Data is buffered for STA at AP");
	DECODEFLAG1(f, flags, 0x40, "Protected flag", "Data is not protected", "Data is protected"	);
	DECODEFLAG1(f, flags, 0x80, "Order flag", "Not strictly ordered", "Strictly ordered");

}



function display_string(px)
{
	var result = "";
	for (i=0; i<px.length; i++) {
		var c = px[i];
		if (32 <= c && c < 127) {
			var c2 = String.fromCharCode(c);
			if (c2 == '<')
				c2 = "&lt;";
			else if (c2 == '>')
				c2 = "&gt;";
			else if (c2 == '&')
				c2 = "&amp;";
			result = result + c2;
		} else {
			result = result + "\\x" + val_to_hex((c>>4)&0xF) + val_to_hex(c&0xf);
		}
	}	
	return result;
}

function ex8(px,offset)
{
    return px[offset];
}
function ex16le(px,offset)
{
	return px[offset] | px[offset+1]<<8;
}
function ex24be(px,offset)
{
	return px[offset+0]<<16 | px[offset+1]<<8 | px[offset+2];
}
function ex32be(px,offset)
{
	return px[offset]<<24 | px[offset+1]<<16 | px[offset+2]<<8 | px[offset+3];
}

function quick_rsn_information(px)
{
	var result = "";
	var offset = 0;
	if (offset+2 <= px.length) {
		version = ex16le(px,offset);
		offset += 2;
	}
	if (offset+4 <= px.length) {
		oui = ex32be(px,offset);
		switch (oui) {
		case 0x50f202: break; /*WPA1 TKIP*/
		case 0x0fac02: break; /*WPA2 TKIP*/
		default: break;
		}
		offset += 4;
	}
	if (offset+2 < px.length) {
		count = ex16le(px,offset);
		offset += 2;
		for (i=0; i<count && offset+4 <= px.length; i++, offset += 4) {
			oui = ex32be(px,offset);
			switch (oui) {
			case 0x50f202: result = result + "TKIP "; break;
			case 0x0fac02: result = result + "TKIP "; break;
			case 0x50f204: result = result + "AES(CCM) "; break;
			case 0x0fac04: result = result + "AES(CCM) "; break;
			default: result = result + "0x" + hex24(oui); break;
			}
		}
	}
	if (offset+2 < px.length) {
		count = ex16le(px,offset);
		offset += 2;
		for (i=0; i<count && offset+4 <= px.length; i++, offset += 4) {
			oui = ex32be(px,offset);
			switch (oui) {
			case 0x50f202: result = result + "PSK "; break;
			case 0x0fac02: result = result + "PSK "; break;
			default: result = result + "0x" + hex24(oui); break;
			}
		}
	}
	return result;
}

function parse_rates(px)
{
	var i;
	var result = "";
	for (i=0; i<px.length; i++) {
		var rate = px[i];
		var isB = "";
		var isOdd = "";

		if (rate & 1) {
			isOdd = ".5";
			rate = rate & 0xFE;
		}
		if (rate & 0x80) {
			isB = "(B)";
			rate = rate & 0x7F;
		}
	
		result = result + (rate>>1) + isOdd + isB + " ";
	}
	return result;
}


/**
 * Decode the Microsoft information element, which contains many
 * differnet sub-elements, such as WPA1 and Multi-media extensions
 */
function decode_microsoft_ie(node, px, field)
{
	if (px.length < 1) {
		DECODEITEM(node, "Too short");
		return;
	}
	var microsoft_type = px[0];
	var offset = 1;
	switch (microsoft_type) {
	case 1:
		f = DECODETREE(node, "Vendor Specific: WPA " + quick_rsn_information(px.slice(1,px.length)), field);
		toggle(f.parentNode);
		if (offset+2 < px.length) {
			version = ex16le(px,offset);
			offset += 2;
			DECODEITEM(f, "Tag Interpretation: " + "WPA IE, type 1, version " + version, field);
			if (version != 1) {
				return;
			}
		}
		offset = decode_wpa_items(f, px, offset);
		
		break;
	case 2:
		DECODEITEM(node, "Windows Multimedia Extensions, version = " + px[1], field);
		break;
	default:
		var str = "";
		f = DECODETREE(node, "Vendor Specific: Microsoft Tag " + microsoft_type + " Len " + px.length);
		toggle(f.parentNode);
		DECODEITEM(f, "Tag Number: " + 221 + "(Vendor Specific)");
		DECODEITEM(f, "Tag length: " + px.length);
		DECODEITEM(f, "Vendor: " + "Microsoft");
		for (i=0; i<10 && i<px.length; i++) {
			c = px[i];
			str = str + val_to_hex((c>>4)&0xF) + val_to_hex(c&0xf);
		}
		if (px.length > 10)
			str = str + "...";
		DECODEITEM(f, "Tag interpretation: " + str);
	}
	
}

/**
 */
function decode_aironet_ie(node, px, field)
{
	if (px.length < 1) {
		DECODEITEM(node, "Too short");
		return;
	}
	var microsoft_type = px[0];
	var offset = 1;
	switch (microsoft_type) {
	case 3:
		DECODEITEM(node, "Aironet CCX version =  " + px[1], field);
		break;
	default:
		var str = "";
		f = DECODETREE(node, "Vendor Specific: Aironet Tag " + microsoft_type + " Len " + px.length, field);
		toggle(f.parentNode);
		DECODEITEM(f, "Tag Number: " + 221 + "(Vendor Specific)");
		DECODEITEM(f, "Tag length: " + px.length);
		DECODEITEM(f, "Vendor: " + "Aironet (Cisco)");
		for (i=0; i<10 && i<px.length; i++) {
			c = px[i];
			str = str + val_to_hex((c>>4)&0xF) + val_to_hex(c&0xf);
		}
		if (px.length > 10)
			str = str + "...";
		DECODEITEM(f, "Tag interpretation: " + str);
	}
	
}

function decode_wpa_items(node, px, offset)
{
	if (offset+4 <= px.length) {
		oui = ex32be(px,offset);
		switch (oui) {
		case 0x0fac02:
		case 0x50f202:
			DECODEITEM(f, "Tag Interpretation: " + "Multicast cipher suite: TKIP");
			break;
		default:
			DECODEITEM(f, "Tag Interpretation: " + "Multicast cipher suite: 0x" + hex24(oui));
		}
		offset += 4;
	}
	if (offset+2 <= px.length) {
		count = ex16le(px,offset);
		offset += 2;
		DECODEITEM(f, "Tag Interpretation: " + "# of unicast cipher suites: " + count);
		for (i=0; i<count && offset+4 <= px.length; i++, offset += 4) {
			oui = ex32be(px,offset);
			switch (oui) {
			case 0x0fac02:
			case 0x50f202:
				DECODEITEM(f, "Tag Interpretation: " + "Unicast cipher suite "+(i+1)+": TKIP");
				break;
			case 0x0fac04:
			case 0x50f204:
				DECODEITEM(f, "Tag Interpretation: " + "Unicast cipher suite "+(i+1)+": AES (CCM)");
				break;
			default:
				DECODEITEM(f, "Tag Interpretation: " + "Unicast cipher suite "+(i+1)+": 0x"+hex24(oui));
			}
		}
	}
	if (offset+2 <= px.length) {
		count = ex16le(px,offset);
		offset += 2;
		DECODEITEM(f, "Tag Interpretation: " + "# of auth key management suites: " + count);
		for (i=0; i<count && offset+4 <= px.length; i++, offset += 4) {
			oui = ex32be(px,offset);
			switch (oui) {
			case 0x0fac02:
			case 0x50f202:
				DECODEITEM(f, "Tag Interpretation: " + "auth key management suite "+(i+1)+": PSK");
				break;
			default:
				DECODEITEM(f, "Tag Interpretation: " + "auth key management suite "+(i+1)+": 0x"+hex24(oui));
			}
		}
	}
	return offset;
}

function decode_tagged_parm(node, tag, field)
{
    var px = field.slice();
    
	switch (tag) {
	case 0: /* SSID */
        var d = field.toDisplayString();
		DECODEITEM(node, 'SSID parameter set: "' + d + '"', field);
		break;
	case 1: /* Supported Rates */
		d = parse_rates(field.slice());
		DECODEITEM(node, "Supported rates: " + d + "[Mbps]", field);
		break;
	case 3:
		if (field.len() == 1) {
            DECODEITEM(node, "DS Parameter set: Current Channel: " + field.byteAt(0), field.sub(0,1));
		} else {
			f = DECODETREE(node, "DS Parameter set: Length: " + field.len(), field);
			toggle(f.parentNode);
		}
		break;
	case 5: /*Traffic Indication Map (TIM)*/
		break;
	case 6: /* ATIM Window for IBSS (ad-hoc) */
		if (px.length < 2) {
			DECODEITEM(node, "Tag length "+px.length+" too short, must be >= 2", field);
		} else {
			var val = ex16le(px,0);
			DECODEITEM(node, "IBSS Parameter set: ATIM window " + val, field);
		}
		break;
            
        case 7: /* Country Info */
            if (px.length < 2) {
                DECODEITEM(node, "Tag length "+px.length+" too short, must be >= 2", field);
            } else {
                d = display_string(px.slice(0,2));
                DECODEITEM(node, "Country Info: " + d, field);
            }
            break;
        break;
            
        case 32: /* Power Constraint */
            if (px.length < 1) {
                DECODEITEM(node, "Tag length "+px.length+" too short, must be >= 1", field);
            } else {
                d = ex8(px,0);
                DECODEITEM(node, "Power Constraint: " + d, field);
            }
            break;
            
        case 45: /* HT Capabilities (802.11n D1.10) */
            f = DECODETREE(node, "HT Capabilities (802.11n D1.10)", field);
            toggle(f.parentNode);
            if (px.length >= 2) {
                var f2;
                var flags = ex16le(px,0);
                f2 = DECODETREE(f, "HT Capabilities: " + NUMHEX16LE(px,0), field.sub(0,2));
                toggle(f2.parentNode);
                DECODEFLAG1(f2, flags, 0x0001, "LDPC Coding Capability", "Not Supported", "Supported");
                DECODEFLAG1(f2, flags, 0x0002, "Channel Width", "20mhz", "40mhz");
            }
            if (px.length >= 3) {
                f2 = DECODETREE(f, "A-MPDU Parameters: " + NUMHEX8(px,2), field.sub(2,3));
            }
            if (px.length >= 3 + 16) {
                f2 = DECODETREE(f, "Rx Modulation/Ecoding Scheme " , field.sub(3,3+16));
            }
            if (px.length >= 19 + 2) {
                f2 = DECODETREE(f, "Extended Capabilities: " + NUMHEX16LE(px,19), field.sub(19,19+2));
            }
            if (px.length >= 21 + 4) {
                f2 = DECODETREE(f, "Transmit Beam Forming (TxBF): " + NUMHEX32LE(px,21), field.sub(21,21 + 4));
            }
            if (px.length >= 25 + 1) {
                f2 = DECODETREE(f, "Antenna Selectection (ASEL): " + NUMHEX8(px,25), field.sub(25,25 + 1));
            }
            break;
            
	case 42:
	case 47:
		if (px.length < 1) {
			DECODEITEM(node, "Tag length "+px.length+" too short, must be >= 1", field);
		} else {
			DECODEITEM(node, "ERP Information: " + NUMHEX8(px,0), field);			
		}
		break;
	case 48: /* WPA2 RSN Information */
		if (px.length < 2) {
			DECODEITEM(node, "Tag length "+px.length+" too short, must be >= 2", field);
		} else {
			f = DECODETREE(node, "RSN Information: WPA2 " + quick_rsn_information(px), field);
			toggle(f.parentNode);
			DECODEITEM(f, "Tag Number: " + tag);
			DECODEITEM(f, "Tag length: " + px.length);
			offset = 0;
			if (offset+2 < px.length) {
				version = ex16le(px,offset);
				DECODEITEM(f, "Tag Interpretation: " + "RSN IE, version " + version);
				offset += 2;
			}
			offset = decode_wpa_items(f, px, offset);
		}
		break;
	case 50: /* Extended Supported Rates */
		d = parse_rates(px);
		DECODEITEM(node, "Extended Supported Rates: " + d + "[Mbps]", field);
		break;
            
        case 61:
            f = DECODETREE(node, "HT Information (802.11n D1.10)", field);
            toggle(f.parentNode);
            break;
            
        case 74:
            f = DECODETREE(node, "Overlapping BSS Scan Parameters", field);
            toggle(f.parentNode);
            if (px.length >= 14) {
                DECODEITEM(f, "Scan Passive Dwell: "+ex16le(px,0), field.sub(0, 2));
                DECODEITEM(f, "Scan Active Dwell: "+ex16le(px,2), field.sub(2, 4));
                DECODEITEM(f, "Channel Width Trigger Scan Interval: "+ex16le(px,4), field.sub(4, 6));
                DECODEITEM(f, "Scan Passive Total Per Channel: "+ex16le(px,6), field.sub(6, 8));
                DECODEITEM(f, "Scan Active Total Per Channel: "+ex16le(px,8), field.sub(8, 10));
                DECODEITEM(f, "Width Channel Transition Delay Factor: "+ex16le(px,10), field.sub(10, 12));
                DECODEITEM(f, "Scan Activity Threshold: "+ex16le(px,12), field.sub(12, 14));
            }
            break;
        case 127: /* EXTENDED CAPABILITIES */
            f = DECODETREE(node, "Extended Capabilities", field);
            toggle(f.parentNode);
            if (px.length >= 8) {
                f2 = DECODETREE(f, "Octet 1: "+NUMHEX8(px,0), field.sub(0, 1));
                DECODEFLAG1(f2, px[0], 0x01, "20/40 BSS Coexistance", "no", "yes");
                DECODEFLAG1(f2, px[0], 0x02, "On-demand beacon", "no", "yes");
                DECODEFLAG1(f2, px[0], 0x04, "Extended Channel Switching", "no", "yes");
                DECODEFLAG1(f2, px[0], 0x08, "WAVE indication", "no", "yes");
                DECODEFLAG1(f2, px[0], 0x10, "PSMP", "no", "yes");
                DECODEFLAG1(f2, px[0], 0x20, "(Reserved)", "no", "yes");
                DECODEFLAG1(f2, px[0], 0x40, "S-PSMP Support", "no", "yes");
                DECODEFLAG1(f2, px[0], 0x80, "Event", "no", "yes");

                f2 = DECODETREE(f, "Octet 2: "+NUMHEX8(px,1), field.sub(1, 2));
                DECODEFLAG1(f2, px[1], 0x01, "Diagnostics", "no", "yes");
                DECODEFLAG1(f2, px[1], 0x02, "Multicast", "no", "yes");
                DECODEFLAG1(f2, px[1], 0x04, "Location Tracking", "no", "yes");
                DECODEFLAG1(f2, px[1], 0x08, "FMS", "no", "yes");
                DECODEFLAG1(f2, px[1], 0x10, "Proxy ARP", "no", "yes");
                DECODEFLAG1(f2, px[1], 0x20, "Collocated Interference Reporting", "no", "yes");
                DECODEFLAG1(f2, px[1], 0x40, "Civic Location", "no", "yes");
                DECODEFLAG1(f2, px[1], 0x80, "Geospatial Location", "no", "yes");
                
                f2 = DECODETREE(f, "Octet 3: "+NUMHEX8(px,2), field.sub(2, 3));
                DECODEFLAG1(f2, px[2], 0x01, "TFS", "no", "yes");
                DECODEFLAG1(f2, px[2], 0x02, "WNM-Sleep Mode", "no", "yes");
                DECODEFLAG1(f2, px[2], 0x04, "TIM Broadcast", "no", "yes");
                DECODEFLAG1(f2, px[2], 0x08, "BSS Transition", "no", "yes");
                DECODEFLAG1(f2, px[2], 0x10, "QoS Traffic Capability", "no", "yes");
                DECODEFLAG1(f2, px[2], 0x20, "AC Station Count", "no", "yes");
                DECODEFLAG1(f2, px[2], 0x40, "Multiple BSSID", "no", "yes");
                DECODEFLAG1(f2, px[2], 0x80, "Timing Measurement", "no", "yes");

                f2 = DECODETREE(f, "Octet 4: "+NUMHEX8(px,3), field.sub(3, 4));
                DECODEFLAG1(f2, px[3], 0x01, "Channel Usage", "no", "yes");
                DECODEFLAG1(f2, px[3], 0x02, "SSID List", "no", "yes");
                DECODEFLAG1(f2, px[3], 0x04, "DMS", "no", "yes");
                DECODEFLAG1(f2, px[3], 0x08, "UTC TSF Offset", "no", "yes");
                DECODEFLAG1(f2, px[3], 0x10, "Peer U-APSD Buffer STA Support", "no", "yes");
                DECODEFLAG1(f2, px[3], 0x20, "TDLS Peer PSM Support", "no", "yes");
                DECODEFLAG1(f2, px[3], 0x40, "TDLS Channel Switching", "no", "yes");
                DECODEFLAG1(f2, px[3], 0x80, "interworking", "no", "yes");

                f2 = DECODETREE(f, "Octet 5: "+NUMHEX8(px,4), field.sub(4, 5));
                DECODEFLAG1(f2, px[4], 0x01, "QoS Map", "no", "yes");
                DECODEFLAG1(f2, px[4], 0x02, "EBR", "no", "yes");
                DECODEFLAG1(f2, px[4], 0x04, "SSPN Interface", "no", "yes");
                DECODEFLAG1(f2, px[4], 0x08, "(Reserved)", "no", "yes");
                DECODEFLAG1(f2, px[4], 0x10, "MSGCF Capability", "no", "yes");
                DECODEFLAG1(f2, px[4], 0x20, "TDLS Support", "no", "yes");
                DECODEFLAG1(f2, px[4], 0x40, "TDLS Prohibited", "no", "yes");
                DECODEFLAG1(f2, px[4], 0x80, "TDLS Channel Switching", "no", "yes");

                f2 = DECODETREE(f, "Octet 6: "+NUMHEX8(px,5), field.sub(5, 6));
                DECODEFLAG1(f2, px[5], 0x01, "Reject Unadmitted Frame", "no", "yes");
                DECODEFLAG1(f2, px[5], 0x0E, "Service Interval Granularity", "5ms", "10ms", "15ms", "20ms");
                DECODEFLAG1(f2, px[5], 0x10, "Identifier Location", "no", "yes");
                DECODEFLAG1(f2, px[5], 0x20, "U-APSD Coexistence", "no", "yes");
                DECODEFLAG1(f2, px[5], 0x40, "WNM-Notification", "no", "yes");
                DECODEFLAG1(f2, px[5], 0x80, "QAB Capability", "no", "yes");

                f2 = DECODETREE(f, "Octet 7: "+NUMHEX8(px,6), field.sub(6, 7));
                DECODEFLAG1(f2, px[6], 0x01, "UTF-8 SSID", "no", "yes");
                DECODEFLAG1(f2, px[6], 0xFE, "(Reserved)", 0);

                f2 = DECODETREE(f, "Octet 8: "+NUMHEX8(px,7), field.sub(7, 8));
                DECODEFLAG1(f2, px[7], 0x1F, "(Reserved)", 0);
                DECODEFLAG1(f2, px[7], 0x20, "TDLS Wider Bandwidth", "no", "yes");
                DECODEFLAG1(f2, px[7], 0x40, "Operating Mode Notfication", "no", "yes");
                DECODEFLAG1(f2, px[7], 0x80, "Max Number of MSDUs in A-MSDU", "0", "1");

            }
            break;

	case 0x85:
		var cisco_name = "";
		if (px.length > 26) {
			cisco_name = px.slice(10,16);
			while (cisco_name.length > 0 && cisco_name[cisco_name.length-1] == 0)
				cisco_name = cisco_name.slice(0,cisco_name.length-1);
			cisco_name = display_string(cisco_name);
		}
		DECODEITEM(node, "Cisco name: " + cisco_name, field);
		break;
	case 221:
		if (px.length < 3) {
			DECODEITEM(node, "Tag length "+px.length+" too short, must be >= 3", field);
		} else {
			oui = ex24be(px,0);
			switch (oui) {
			case 0x001018:
				DECODEITEM(node, "Vendor Specific: " + "Broadcom", field);
				break;
			case 0x0050f2:
				decode_microsoft_ie(node, px.slice(3,px.length), field);
				break;
			case 0x004096:
				decode_aironet_ie(node, px.slice(3,px.length), field);
				break;
            case 0x0037f:
                    if (px.length < 4) {
                        DECODEITEM(node, "Vendor Specific: " + "Atheros", field);
                    } else switch (px[3]) {
                        case 1:
                            f = DECODETREE(node, "Vendor Specific: " + "Atheros - Advanced Capability", field);
                            toggle(f.parentNode);
                            decode_atheros_advanced_capability(f, field.sub(4));
                            break;
                        default:
                            DECODEITEM(node, "Vendor Specific: " + "Atheros", field);
                            break;
                    }
                break;
			default:
				DECODEITEM(node, "Vendor Specific: " + NUMHEX24BE(px,0), field);
			}
		}
		break;

	default:
		var str = "";
		f = DECODETREE(node, "Reserved tag number: Tag " + tag + " Len " + px.length, field);
		toggle(f.parentNode);
		DECODEITEM(f, "Tag Number: " + tag, field.sub(-2,1), px);
		DECODEITEM(f, "Tag length: " + px.length, field.sub(-1,1), px);
		for (i=0; i<10 && i<px.length; i++) {
			c = px[i];
			str = str + val_to_hex((c>>4)&0xF) + val_to_hex(c&0xf);
		}
		if (px.length > 10)
			str = str + "...";
		DECODEITEM(f, "Tag interpretation: " + str, field.sub(2),px);
	}
}

function decode_tagged_parms(node, field)
{
	var t = DECODETREE(node, "Tagged parameters (" + field.len() + " bytes)", field);
	
	var i = 0;
	while (i < field.len()) {
		tag = field.byteAt(i++);
		if (i >= field.len())
			break;
		len = field.byteAt(i++);
		if (len > field.len()-i)
			len = field.len()-i;
		decode_tagged_parm(t, tag, field.sub(i, len));
		i += len;
	}
}

function decode_capability(node, px, offset, r)
{
	var c;
	var flags = px[offset] + px[offset]*256;

	c = DECODETREE(fixed, "Capability Information: " + NUMHEX16LE(px,offset), r);
	toggle(c.parentNode);
	
	DECODEFLAG1_16(c, flags, 0x0001, r, "ESS capabilities",		{0:"Transmitter is a STA",				1:"Transmitter is an AP"});
    DECODEFLAG1_16(c, flags, 0x0002, r, "IBSS status",			{0:"Transmitter belongs to a BSS",		1:"Transmitter belongs to an IBSS"});
    DECODEFLAG1_16(c, flags, 0x020C, r, "CFP participation capabilities", {0:"No point coordinator at AP"});
    DECODEFLAG1_16(c, flags, 0x0010, r, "Privacy",				{0:"cannot support WEP",1:"can support WEP"});
    DECODEFLAG1_16(c, flags, 0x0020, r, "Short Preamble",		{0:"not allowed",		1:"allowed"});
    DECODEFLAG1_16(c, flags, 0x0040, r, "PBCC",					{0:"not allowed",		1:"allowed"});
    DECODEFLAG1_16(c, flags, 0x0080, r, "Channel Agility",		{0:"not in use",		1:"in use"});
    DECODEFLAG1_16(c, flags, 0x0100, r, "Spectrum Management",	{0:"not required",		1:"required"});
    DECODEFLAG1_16(c, flags, 0x0400, r, "Short Slot Time",		{0:"not in use",		1:"in use"});
    DECODEFLAG1_16(c, flags, 0x0800, r, "Automatic Power Save Delivery", {0:"not implemented",		1:"implemented"});
    DECODEFLAG1_16(c, flags, 0x2000, r, "DSSS-OFDM",			{0:"not allowed",		1:"allowed"});
    DECODEFLAG1_16(c, flags, 0x4000, r, "Delayed Block Ack",	{0:"not implemented",	1:"implemented"});
    DECODEFLAG1_16(c, flags, 0x8000, r, "Immediate Block Ack",	{0:"not implemented",	1:"implemented"});
}
function decode_wifi_beacon(node, px)
{
    var field = new Range(0, px.length, px);
	if (field.len() < 24)
		return node;
	
	header_length = 24;
	header = decode_mgmnt_header(node, px);

	parms = DECODETREE(node, "IEEE 802.11 wireless LAN management frame", field.sub(24));
	
	if (field.len() >= 36) {
		var interval = ((px[32] + px[33]*256.0) * 1024.0) / 1000000.0;
		var flags = px[34] + px[35]*256;
		fixed = DECODETREE(parms, "Fixed parameters (12 bytes)", field.sub(24,12));
		toggle(fixed.parentNode);
		DECODEITEM(fixed, "Timestamp: " + NUMHEX64LE(px,24), field.sub(24,8));
		DECODEITEM(fixed, "Beacon Interval: " + interval + " [Seconds]", field.sub(32,2));

		decode_capability(fixed, px, 34, field.sub(34,2));
	}

	if (field.len() > 36) {
		decode_tagged_parms(parms, field.sub(36));
	}

	return header;
}

function decode_wifi_associate_request(node, px)
{
	var field = new Range(0, px.length, px);
	if (px.length < 24)
		return node;

	header_length = 24;

	header = decode_mgmnt_header(node, px);

	parms = DECODETREE(node, "IEEE 802.11 wireless LAN management frame", field.sub(24,px.length-24));
	if (px.length >= 28) {
		var interval = ((px[26] + px[27]*256.0) * 1024.0) / 1000000.0;

		fixed = DECODETREE(parms, "Fixed parameters (4 bytes)", field.sub(24,4));
		toggle(fixed.parentNode);
		decode_capability(fixed, px, 24, field.sub(24,2));
		DECODEITEM(fixed, "Listen Interval: " + interval + " [Seconds]", field.sub(26,2));
	}

	if (field.len() >= 28) {
		decode_tagged_parms(parms, field.sub(28));
	}

	return header;
}

function decode_wifi_associate_response(node, px)
{
	var field = new Range(0, px.length, px);
	if (field.len() < 24)
		return node;

	header_length = 24;

	header = decode_mgmnt_header(node, px);

	parms = DECODETREE(node, "IEEE 802.11 wireless LAN management frame", field.sub(24,px.length-24));
	if (px.length >= 30) {
		var status_code = px[26] + px[27]*256;
		var association_id = px[28] + px[29]*256;

		fixed = DECODETREE(parms, "Fixed parameters (6 bytes)", field.sub(24,4));
		toggle(fixed.parentNode);
		decode_capability(fixed, px, 24, field.sub(24,2));
		DECODEITEM(fixed, "Status Code: " + ENUM(status_code,{0:"Successful "}) + PARENSHEX16(status_code), field(26,28,px));
		DECODEITEM(fixed, "Association ID: " + hex16(association_id), field.sub(28,2));
	}

	if (field.len() > 30) {
		decode_tagged_parms(parms, field.sub(30));
	}

	return header;
}

function decode_wifi_deauth(node, px)
{
	var field = new Range(0, px.length, px);
	if (field.len() < 24)
		return node;

	header_length = 24;

	header = decode_mgmnt_header(node, px);

	parms = DECODETREE(node, "IEEE 802.11 wireless LAN management frame", field.sub(24,2));
	if (px.length >= 26) {
		var reason = px[24] + px[25]*256;
		var enumreason = {
			"2": "Previous authentication no longer valid "
		};
		fixed = DECODETREE(parms, "Fixed parameters (2 bytes)", field.sub(24,2));
		toggle(fixed.parentNode);
		DECODEITEM(fixed, "Reason code: " + ENUM(reason,enumreason) + PARENSHEX16(reason), field.sub(24,2));
		
	}

	return header;
}

function decode_mgmnt_header(node, px)
{
	var field = new Range(0, px.length, px);
	var type = {
		0x00: "Association Request ",
		0x00: "Reassociation Request ",
		0x10: "Association Response ",
		0x30: "Reassociation Response ",
		0x50: "Probe Response ",
		0x80: "Beacon ",
		0xb0: "Authentication ",
		0xc0: "Deauthentication ",
	};
	var header;
	var flags2;

	flags2 = px[22] + px[23]*256;

	header = DECODETREE(node, "IEEE 802.11 "+ENUM(px[0],type), field);
	DECODEITEM(header, "Type/Subtype: "+ENUM(px[0],type) + PARENSHEX8(px[0]>>4), field.sub(0,1));
	decode_wifi_framecontrol(header, px);
	duration = ex16le(px,2);
	DECODEITEM(header, "Duration: " + duration, field.sub(2,2));
	DECODEMACADDR(header, "Destination address", px, 4);
	DECODEMACADDR(header, "Source address", px, 10);
	DECODEMACADDR(header, "BSS Id", px, 16);
	DECODEITEM(header, "Fragment number: " + (flags2&0xF), field.sub(22,1));
	DECODEITEM(header, "Sequence number: " + (flags2>>4), field.sub(22,2));

	return header;
}

function decode_wifi_auth(node, px)
{
	var field = Range(0, px.lelngth, px);
	if (px.length < 24)
		return node;

	header_length = 24;

	header = decode_mgmnt_header(node, px);

	parms = DECODETREE(node, "IEEE 802.11 wireless LAN management frame", field.sub(24,4));
	if (px.length >= 28) {
		var algo = px[24] + px[25]*256;
		var seq = px[26] + px[27]*256;
		var enumalgo = {
			"0": "Open System "
		};

		fixed = DECODETREE(parms, "Fixed parameters (4 bytes)", field.sub(24,2));
		toggle(fixed.parentNode);
		DECODEITEM(fixed, "Authentication Algorithm: "+ENUM(algo,enumalgo) + PARENSHEX16(algo), field.sub(24,2));
		DECODEITEM(fixed, "Authentication SEQ: 0x"+ hex16(seq), field.sub(26,4));
	}

	return header;
}


function ENUM(n,vals)
{
	if (vals[n])
		return vals[n];
	else
		return "unknown";
}

function decode_wifi(node, bytes)
{
	if (bytes.length == 0)
		return;

	switch (bytes[0]) {
	case 0x00:
	case 0x20:
		return decode_wifi_associate_request(node, bytes);
	case 0x10:
	case 0x30: /* Re-association response*/
		return decode_wifi_associate_response(node, bytes);
	case 0x80: 
	case 0x50:
		return decode_wifi_beacon(node, bytes);
	case 0xc0:
		return decode_wifi_deauth(node, bytes);
	case 0xb0:
		return decode_wifi_auth(node, bytes);
	default:
		header = DECODETREE(node, "IEEE 802.11 unknown frame");
		DECODEITEM(header, "Type/Subtype: unknown " + PARENSHEX8(bytes[0]));
		return header;
	}
}

function PARENSHEX8(val)
{
	return "(0x" + val_to_hex((val>>4)&0xF) + val_to_hex(val&0xF) + ")";
}
function PARENSHEX16(val)
{
	return "(0x" 
			+ val_to_hex((val>>4)&0xF) + val_to_hex(val&0xF) 
			+ val_to_hex((val>>12)&0xF) + val_to_hex((val>>8)&0xF) 
			+ ")";
}
function NUMHEX16LE(bytes,offset)
{
	var val = bytes[offset] + bytes[offset+1]*256;
	return "0x"
	        + val_to_hex((val>>12)&0xF) + val_to_hex((val>>8)&0xF) 
			+ val_to_hex((val>>4)&0xF) + val_to_hex((val>>0)&0xF) 
			;
}
function NUMHEX8(bytes,offset)
{
	var val = bytes[offset];
	return "0x"
			+ val_to_hex((val>>4)&0xF) + val_to_hex((val>>0)&0xF) 
			;
}

function NUMHEX64LE(bytes,offset)
{
	var result = "0x";
	for (i=0; i<8; i++) {
		val = bytes[offset+7-i];
		result = result + val_to_hex((val>>4)&0xF) + val_to_hex((val>>0)&0xF);
	}
	return result;
}
function NUMHEX24LE(bytes,offset)
{
    var result = "0x";
    for (i=0; i<3; i++) {
        val = bytes[offset+2-i];
        result = result + val_to_hex((val>>4)&0xF) + val_to_hex((val>>0)&0xF);
    }
    return result;
}
function NUMHEX24BE(bytes,offset)
{
    var result = "0x";
    for (i=0; i<3; i++) {
        val = bytes[offset+i];
        result = result + val_to_hex((val>>4)&0xF) + val_to_hex((val>>0)&0xF);
    }
    return result;
}
function NUMHEX32LE(bytes,offset)
{
    var result = "0x";
    for (i=0; i<4; i++) {
        val = bytes[offset+3-i];
        result = result + val_to_hex((val>>4)&0xF) + val_to_hex((val>>0)&0xF);
    }
    return result;
}

function hex8(val)
{
	return val_to_hex((val>>4)&0xF) + val_to_hex(val&0xF);
}
function hex16(val)
{
	return hex8(val>>8) + hex8(val);
}
function hex24(val)
{
	return hex8(val>>16) + hex8(val>>8) + hex8(val);
}
function hex32(val)
{
	return hex8(val>>24) + hex8(val>>16) + hex8(val>>8) + hex8(val);
}

function BIT(flags,mask,i)
{
	if ((mask & i) == 0)
		return ".";
	if ((mask & flags & i) == 0)
		return "0";
	return "1";	
}

function macaddr_to_hex(px, offset)
{
	var addr = "";

	for (i=0; i<6; i++) {
		addr = addr + val_to_hex(px[offset+i]>>4) + val_to_hex(px[offset+i]&0xF);
		if (i<5)
			addr = addr + ":";
	}
	return addr;
}

function DECODEMACADDR(node, name, px, offset)
{
	var addr = "";

	for (i=0; i<6; i++) {
		addr = addr + val_to_hex(px[offset+i]>>4) + val_to_hex(px[offset+i]&0xF);
		if (i<5)
			addr = addr + ":";
	}

	if (macnames && macnames[addr]) {
		addr = '"' + macnames[addr] + '" (' + addr + ")";
	}

	var item = DECODEITEM(node, name + ": " + addr, ({start:offset, stop:offset+6}));

	//item.setAttribute("hexstart", offset);
	//item.setAttribute("hexstop", offset+6);
	return item;
}

function DECODEFLAG1(node, flags, mask, name, value0, value1)
{
	var bits = "";
	bits =  BIT(flags,mask,0x80) +
			BIT(flags,mask,0x40) +
			BIT(flags,mask,0x20) +
			BIT(flags,mask,0x10) +
			BIT(flags,mask,0x08) +
			BIT(flags,mask,0x04) +
			BIT(flags,mask,0x02) +
			BIT(flags,mask,0x01);
	DECODEITEM(node, bits + " = " + name + ": " + ((mask&flags)?value1:value0) );
}

function DECODEFLAG1_16(node, flags, mask, r, name, e)
{
	var bits = "";
	for (i=0; i<16; i++) {
		bits = bits + BIT(flags,mask,1<<(15-i));
		if (i == 3) bits = bits + " ";
		if (i == 7) bits = bits + " ";
		if (i == 11) bits = bits + " ";

	}
	while (mask != 0 && (mask&1) == 0) {
		mask = mask >> 1;
		flags = flags >> 1;
	}
	DECODEITEM(node, bits + " = " + name + ": " + ENUM((mask&flags), e), r );
}


/**
 * Add a line to the protocol decode with the specified text contents
 * and associated field in the hex field.
 */
function DECODEITEM(node,text,field)
{
	item = document.createElement("li");
	item.className = "treenorm";
	node.appendChild(item);

	div = document.createElement("div");
	div.setAttribute("class", "clk2");
	
	/* Give the <div> element a 'tabindex' attribute. This makes it so that
	 * the <div> element can receive onFocus events. This is needed for
	 * Firefox, although Internet Explorer already sends onFocus events to
	 * <div> elements without this trick. A 'tabindex' of -1 makes it so
	 * you can't tab to it, but it otherwise behaves as if you can (such
	 * as being able to click on it and give focus). A 'tabindex' of 0
	 * gives it an automatically generated position in the tab order.
	 * a positive value will give it a fixed location in the tab order. */
	div.setAttribute("tabindex", "0");

	/* Process the focus change on the <div> elements. Note that focus
	 * is a concept for <form> input elements, it's a hack to make it work
	 * for <div> Internet Explorer supports the concept. Firefox needs 
	 * some coaching by adding a 'tabindex' value. This works on Chrome,
	 * but last I heard, it does not work on Safari. I don't know about
	 * Opera
	 */
	div.setAttribute("onFocus", "do_shade_hex(this.parentNode)");
	item.appendChild(div);

	div.innerHTML = text;

	if (field != undefined) {
		item.setAttribute("hexstart", field.start);
		item.setAttribute("hexstop", field.stop);
	}
	return item;
}

function g(t,e)
{
	var x=e.clientX - t.offsetLeft;
	var y=e.clientY - t.offsetRight;

	if (x < 32)
		return true;
	else
		return false;
}

function DECODETREE(node, text, field)
{
	item = document.createElement("li");
	item.className = "treeshow";
	node.appendChild(item);

	div = document.createElement("div");
	div.setAttribute("class", "clk");
	div.setAttribute("tabindex", "0");
	div.setAttribute("onclick", "g(this,event)?toggle(this.parentNode):0");
	div.setAttribute("onfocus", "do_shade_hex(this.parentNode)");
	div.setAttribute("onkeydown", "tree_onKeyDown(this.parentNode,event)");
	div.innerHTML = text;
	item.appendChild(div);

	ul = document.createElement("ul");
	item.appendChild(ul);

	if (field != undefined) {
		item.setAttribute("hexstart", field.start);
		item.setAttribute("hexstop", field.stop);
	}
	return ul;
}

function toggle(x)
{
	x.className = (x.className=='treeshow') ? 'treehide' : 'treeshow';
}

function tree_nav_up(node)
{
	var x;
	for (x = node.parentNode; x; x = x.parentNode) {
		if (x.nodeName == "LI")
			return x;
	}
	return x;
}

function show_coords(t, event)
{
	var x=event.clientX - t.offsetLeft;
	var y=event.clientY - t.offsetRight;
	alert("X coords: " + x + ", Y coords: " + y);
}

/**
 * Handles the event when the user presses a key on a tree
 * root. We are looking for curse keys (up,down,left,right).
 * A <left> key closes a tree, a <right> key expands the tree.
 */
function tree_onKeyDown(node,e)
{
	var keynum;

	if (window.event) {
		/* Internet Explorer */
		keynum = e.keyCode;
	} else if (e.which)	{
		/*  Netscape, Firefox, Opera */
		keynum = e.which;
	}

	switch (keynum) {
	case 37: /* left */
		var x;
		if (node.className == "treeshow")
			toggle(node);
		else if (node.className == "treehide") {
			var li = tree_nav_up(node);
			li.focus();
		}
		break;
	case 38: /* up */
		break;
	case 39: /* right */
		if (node.className == "treehide")
			toggle(node);
		break;
	case 40: /* down */
		break;
	default:
		break;
	}
}


function treenode_add(loc, title)
{
	var details;
	var frame;

	details = document.getElementById("details");
	frame = details.getElementById("frame");

}

function hex_val(c)
{
	switch (c) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': return 10;
	case 'b': return 11;
	case 'c': return 12;
	case 'd': return 13;
	case 'e': return 14;
	case 'f': return 15;
	case 'A': return 10;
	case 'B': return 11;
	case 'C': return 12;
	case 'D': return 13;
	case 'E': return 14;
	case 'F': return 15;
	default: return 16;
	}
}

function hex_to_binary(str)
{
	var result = new Array();
	var i;

	for (i=0; i<str.length; i++) {
		c = str.charAt(i);
		if (c == ' ')
			continue;
		if (c == '\n')
			continue;
		if (c == '&') {
			while (i<str.length && str.charAt(i) != ';')
				i++;
			continue;
		}
		if (c == '<') {
			while (i<str.length && str.charAt(i) != '>')
				i++;
			continue;
		}
		val = hex_val(c);

		if (val >= 16)
			continue;

		i++;
		if (i >= str.length)
			break;

		var val2 = hex_val(str.charAt(i));
		if (val2 < 16) {
			val = val * 16 + val2;
		}
		result.push(val);
	}
	return result;
}

function val_to_hex(v)
{
	switch (v) {
	case 0: return '0';
	case 1: return '1';
	case 2: return '2';
	case 3: return '3';
	case 4: return '4';
	case 5: return '5';
	case 6: return '6';
	case 7: return '7';
	case 8: return '8';
	case 9: return '9';
	case 10: return 'a';
	case 11: return 'b';
	case 12: return 'c';
	case 13: return 'd';
	case 14: return 'e';
	case 15: return 'f';
	default: return 'X';
	}
}

function binary_to_hex(bin)
{
	var result = "";
	var i;

	for (i=0; i<bin.length; i++) {
		var v = bin[i];
		var c = val_to_hex((v>>4)&0xF) + val_to_hex(v&0xF) + " ";
		result = result + c;
	}
	return result;
}


