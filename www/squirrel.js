var xmlhttp;
var last_update = 0;

var sort_direction = 0;

function loadXMLDoc(url)
{
	xmlhttp=null;

	if (window.XMLHttpRequest) {
		// code for IE7, Firefox, Mozilla, etc.
		xmlhttp=new XMLHttpRequest();
	} else if (window.ActiveXObject) {
		// code for IE5, IE6
		xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
	}

	if (xmlhttp != null) {
		xmlhttp.onreadystatechange = onResponse;
		xmlhttp.open("GET",url,true);
		xmlhttp.send(null);
	}

}
function refresh_xml(url, handle_response)
{
	xmlhttp=null;

	if (window.XMLHttpRequest) {
		// code for IE7, Firefox, Mozilla, etc.
		xmlhttp=new XMLHttpRequest();
	} else if (window.ActiveXObject) {
		// code for IE5, IE6
		xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
	}

	if (xmlhttp != null) {
		xmlhttp.onreadystatechange = handle_response;
		xmlhttp.open("GET",url,true);
		xmlhttp.send(null);
	}

}


function refresh()
{
	loadXMLDoc("bssids.xml?last_update="+last_update);
}

function refresh_probers()
{
	loadXMLDoc("probers.xml?last_update="+last_update);
}


function refresh_bssid_item()
{
    var seenlast = document.getElementById("seenlast").getAttribute("value");
	refresh_xml(bssid_item_address + ".xml?seenlast=" + seenlast, handle_bssid_item);
}

function update_table_cell(tableId, rowId, cellId, newValue)
{
	var table;
    var row;
	var cell;
    var oldValue = newValue;
    
	/* Format the raw time into a JavaScript Date local string */
	if (cellId == "seenfirst" || cellId == "seenlast") {
		var d = new Date(parseInt(newValue)*1000);
		var now = new Date();

		if (now.toLocaleDateString() == d.toLocaleDateString())
			newValue = d.toLocaleTimeString();
		else
			newValue = d.toLocaleDateString() + "  " + d.toLocaleTimeString();
	}

    table = document.getElementById(tableId);
    if (table)
        row = table.rows[rowId]; //row = table.rows[rowId];
	else
		alert("table["+tableId+"] does not exist");

    if (row)
        cell = row.cells[cellId];
	else
		alert("table["+tableId+"] row["+rowId+"] does not exist");
    
	if (cell) {
		if (cell.innerHTML == newValue) {
			; //cell.className = "inactive";
			return 0;
		} else {
			//cell.className = "active";
            if (cellId == "seenfirst" || cellId == "seenlast")
                cell.setAttribute("value", oldValue);
			cell.innerHTML = newValue;
			return 1;
		}
	} else
		alert("table["+tableId+"] row["+rowId+"] cell["+cellId+"] does not exist");
	return 0;
}

function xml_update_cell(tableId, cellId, base)
{
	var rowId;
	var x;


	try {

		// Get BSSID from XML data
		rowId = base.getAttribute("id");

		x = base.getElementsByTagName(cellId);
		if (x.length > 0 && x[0].firstChild) {
			try {
				return update_table_cell(tableId, rowId, cellId, x[0].firstChild.nodeValue);
			} catch (er) {
				alert("["+table+","+rowId+","+cellId+"]  " + er);
			}
		}
	} catch (er) {
		alert(er);
	}
	return 0;
}

function xml_update_cell2(tableId, rowId, cellId, base)
{
	var table;
    var row;
	var cell;
	var y;
	var innerHTML = "";

	try {
		var x;
		x = base.getElementsByTagName(cellId);
		if (x.length > 0 && x[0].firstChild) {
			try {
				innerHTML = x[0].firstChild.nodeValue;
			} catch (er) {
				alert("*1* " + "["+table+","+cellId+"]  " + er);
			}
		}
	} catch (er) {
		alert("*2* "+er);
	}

    table = document.getElementById(tableId);
    if (!table)
		return;

	/* Format the raw time into a JavaScript Date local string */
	if (cellId == "seenfirst" || cellId == "seenlast") {
		var d = new Date(parseInt(innerHTML)*1000);
		var now = new Date();

		if (now.toLocaleDateString() == d.toLocaleDateString())
			innerHTML = d.toLocaleTimeString();
		else
			innerHTML = d.toLocaleDateString() + "  " + d.toLocaleTimeString();
	}

	for (y=0; y<table.rows.length; y++) {
		var x;
		for (x=0; x<table.rows[y].cells.length; x++) {
			cell = table.rows[y].cells[x];
			if (cell.id == cellId) {
				if (cell.innerHTML == innerHTML)
					cell.className = "inactive";
				else {
					cell.className = "active";
					cell.innerHTML = innerHTML;
				}
			}
		}
	}
	return;


}


function update_display_bases(bases)
{
	var i;
	var rows;

	/*
	 * See if the table exists in the document
	 */
	table = document.getElementById("bssidlist");
	if (!table)
		return;

	/*
	 * Mark all the rows as "inactive" first. Any updated rows
	 * will be then changed back to "active" again.
	 */
	rows = table.rows;
	for (i=0; i<rows.length; i++) {
		var cells = rows[i].cells;
		//for (j=0; j<cells.length; j++)
		//	cells[j].className = "inactive";
		rows[i].className = "inactive";
	}

	/*
	 * Go through the XML document and process each of the 
	 * "base" elements
	 */
	for (i=0; i<bases.length; i++) {
		var base = bases[i];
		var timestamp;

		rowId = base.getAttribute("id");
		timestamp = parseInt(base.getAttribute("timestamp"));

		/*
		 * Record the timestamp of this update. This will be used during the
		 * next update to only retrieve the records that have changed, in 
		 * order to reduce the size of the update. 
		 */
		if (last_update < timestamp) {
			last_update = timestamp;
		}

		if (!table.rows[rowId]) {
			var row;
			var z = rowId;

			try {
			z = base.getElementsByTagName("bssid")[0].firstChild.nodeValue;

			table.insertRow(1);
			row = table.rows[1];
			row.innerHTML = '<td id="bssid" class="bssid"><a href="/bssid/'+rowId+'.html">'+z+'</a></td>' +
							'<td id="manuf" class="manuf"></td>' +
							'<td id="stacount" class="stacount">0</td>' +
							'<td id="power" class="power"></td>' +
							'<td id="beacons" class="beacons"></td>' +
							'<td id="datapackets" class="datapackets"></td>' +
							'<td id="channels" class="channels"></td>' +
							'<td id="speed" class="speed"></td>' +
							'<td id="encryption" class="encryption"></td>' +
							'<td id="cipher" class="cipher"></td>' +
							'<td id="auth" class="auth"></td>' +
							'<td id="adhoc" class="adhoc"></td>' +
							'<td id="essid" class="essid"></td>'
							;
			} catch (er) {
				alert(er);
			}
			row.id = rowId;
		}


		var changes = 0;
		var foobar = 0;

		changes += xml_update_cell("bssidlist", "stacount", base);
		changes += xml_update_cell("bssidlist", "manuf", base);
		changes += xml_update_cell("bssidlist", "power", base);
		changes += xml_update_cell("bssidlist", "beacons", base);
		changes += xml_update_cell("bssidlist", "datapackets", base);
		changes += xml_update_cell("bssidlist", "channels", base);
		changes += xml_update_cell("bssidlist", "speed", base);
		changes += xml_update_cell("bssidlist", "encryption", base);
		changes += xml_update_cell("bssidlist", "cipher", base);
		changes += xml_update_cell("bssidlist", "auth", base);
		changes += xml_update_cell("bssidlist", "adhoc", base);
		changes += xml_update_cell("bssidlist", "essid", base);

		if (changes > 0) {
			table.rows[rowId].className = "active";
		} else {
			table.rows[rowId].className = "inactive";
		}
	}

}

function update_display_probers(bases)
{
	var i;
	var rows;

	/*
	 * Get the table object within the document
	 */
	table = document.getElementById("probers");
	if (!table)
		return;

	/*
	 * Mark all the rows as "inactive" first. Any updated rows
	 * will be then changed back to "active" again.
	 */
	rows = table.rows;
	for (i=0; i<rows.length; i++) {
		rows[i].className = "inactive";
	}

	/*
	 * Go through the XML document and process each of the
	 * records
	 */
	for (i=0; i<bases.length; i++) {
		var base = bases[i];
		var timestamp;

		rowId = base.getAttribute("id");
		timestamp = parseInt(base.getAttribute("timestamp"));
		
		/*
		 * Record the timestamp of this update. This will be used during the
		 * next update to only retrieve the records that have changed, in 
		 * order to reduce the size of the update. 
		 */
		if (last_update < timestamp) {
			last_update = timestamp;
		}


		if (!table.rows[rowId]) {
			var row;
			var z = rowId;

			try {
			z = base.getElementsByTagName("mac")[0].firstChild.nodeValue;

			table.insertRow(1);
			row = table.rows[1];
			row.innerHTML = '<td id="mac" class="mac"><a href="/station/'+rowId+'.html">'+z+'</a></td>' +
                '<td id="manuf" class="manuf"></td>' +
                '<td id="iehash" class="iehash"></td>' +
                '<td id="standard" class="standard"></td>' +
                '<td id="channelwidth" class="channelwidth"></td>' +
                '<td id="power" class="power"></td>' +
                '<td id="probes" class="probes"></td>' +
                '<td id="seenlast" class="seenlast"></td>' +
                '<td id="essids" class="essids"></td>'
                ;
			} catch (er) {
				alert(er);
			}
			row.id = rowId;
		}

		var changes = 0;

        changes += xml_update_cell("probers", "manuf", base);
        changes += xml_update_cell("probers", "iehash", base);
        changes += xml_update_cell("probers", "standard", base);
        changes += xml_update_cell("probers", "channelwidth", base);
		changes += xml_update_cell("probers", "power", base);
		changes += xml_update_cell("probers", "probes", base);
		changes += xml_update_cell("probers", "seenlast", base);
		changes += xml_update_cell("probers", "essids", base);

		if (changes > 0)
			table.rows[rowId].className = "active";
	}

}

function onResponse()
{
	var update;
	var bases;
	var probers;
	var itemcount;

	// Wait until we get a reply back from the server		
	if(xmlhttp.readyState != 4) 
		return;

	// Make sure the reply is "HTTP/1.1 200 OK"
	if(xmlhttp.status != 200)
		return;

	//
	update = xmlhttp.responseXML.documentElement;
	if (!update)
		return;
	if (update.nodeName != "update")
		return; // corrupt XML contents

	itemcount = parseInt(update.getAttribute("count"));
	if (itemcount)
		document.title = "(" + itemcount + ")";

	//alert(update.getAttribute("timestamp"));

	bases = update.getElementsByTagName("base");
	if (bases && bases.length)
		update_display_bases(bases);

	probers = update.getElementsByTagName("prober");
	if (probers && probers.length)
		update_display_probers(probers);

}

function handle_bssid_item()
{
	var update;
	var bases;

	// Wait until we get a reply back from the server		
	if(xmlhttp.readyState != 4) 
		return;

	// Make sure the reply is "HTTP/1.1 200 OK"
	if(xmlhttp.status != 200) {
		return;
	}

	//
	update = xmlhttp.responseXML.documentElement;
	if (!update) {
		alert("No XML Document returned");
		return;
	}
	if (update.nodeName != "bssidupdate") {
		//alert("No BSSIDUPDATE element");
		return; // corrupt XML contents
	}

	// Get the BSSID information
	base = update.getElementsByTagName("base")[0];
	xml_update_cell2("bssids2", "3", "mac", base);
	xml_update_cell2("bssids2", "3", "stacount", base);
	xml_update_cell2("bssids2", "3", "beacons", base);
	xml_update_cell2("bssids2", "1", "dataout", base);
	xml_update_cell2("bssids2", "1", "datain", base);
	xml_update_cell2("bssids2", "4", "power", base);
	xml_update_cell2("bssids2", "4", "channels", base);
	xml_update_cell2("bssids2", "4", "speed", base);
	xml_update_cell2("bssids2", "5", "encryption", base);
	xml_update_cell2("bssids2", "5", "cipher", base);
	xml_update_cell2("bssids2", "5", "auth", base);
	xml_update_cell2("bssids2", "2", "essid", base);
	xml_update_cell2("bssids2", "2", "ctrlout", base);
	xml_update_cell2("bssids2", "2", "ctrlin", base);
	xml_update_cell2("bssids2", "2", "mgmtout", base);
	xml_update_cell2("bssids2", "2", "mgmtin", base);
	xml_update_cell2("bssids2", "2", "seenfirst", base);
	xml_update_cell2("bssids2", "2", "seenlast", base);


	stationlist = update.getElementsByTagName("stationlist")[0];
	stations = stationlist.getElementsByTagName("station");

	for (i=0; i<stations.length; i++) {
		var sta = stations[i];

		rowId = sta.getAttribute("id");
		
		// See if the row exists
		table = document.getElementById("stationlist");
		if (!table) {
			alert("No HTML table");
		}
		if (!table.rows[rowId]) {
			var row;
			var z = rowId;

			try {
			z = sta.getElementsByTagName("macaddr")[0].firstChild.nodeValue;

			table.insertRow(1);
			row = table.rows[1];
			row.innerHTML = 
						  '<td id="station" class="station"><a href="/station/'+rowId+'.html">'+z+'</a></td>' +
						  '<td id="stamanuf" class="stamanuf"></td>' +
						  '<td id="power" class="power"></td>' +
						  '<td id="dataout" class="dataout"></td>' +
						  '<td id="datain"  class="datain" ></td>' +
						  '<td id="ctrlout" class="ctrlout"></td>' +
						  '<td id="ctrlin"  class="ctrlin" ></td>' +
						  '<td id="info" class="info"></td>'
							;
			} catch (er) {
				alert(er);
			}
			row.id = rowId;
		}

		var changes = 0;

		changes += xml_update_cell("stationlist", "stamanuf", sta);
		changes += xml_update_cell("stationlist", "power", sta);
		changes += xml_update_cell("stationlist", "dataout", sta);
		changes += xml_update_cell("stationlist", "datain", sta);
		changes += xml_update_cell("stationlist", "ctrlout", sta);
		changes += xml_update_cell("stationlist", "ctrlin", sta);
		changes += xml_update_cell("stationlist", "info", sta);
	}


}

function nukeRow()
{
	var rowId = "0011216193b0";
	alert(document.getElementById("bssidlist").rows[rowId].id);
	document.getElementById("bssidlist").rows[rowId].id = "nuked";
	alert(document.getElementById("bssidlist").rows[rowId].id);
}

function biggest_entry(table, start, column_id)
{
	var found_index = 0;
	var found_text = "";

	for (i=start; i<table.rows.length; i++) {
		var cell = table.rows[i].cells[column_id].innerHTML;
		if (cell > found_text) {
			found_text = cell;
			found_index = i;
		}
	}

	return found_index;
}
function smallest_entry(table, start, column_id)
{
	var found_index = 0;
	var found_text = "";

	for (i=start; i<table.rows.length; i++) {
		var cell = table.rows[i].cells[column_id].innerHTML;
		if (cell < found_text) {
			found_text = cell;
			found_index = i;
		}
	}

	return found_index;
}

function do_menu(node)
{
	var item;
	var table;
	var row;
	var i;
	var column_index = 0;
	var list = {};

	/* Find which column we are doing */
	row = node.parentNode;
	for (i=0; i<row.cells.length; i++) {
		if (row.cells[i] == node) {
			column_index = i;
			break;
		}
	}


	/* Go through the entire table */
	table = row.parentNode;



	var j;
	for (j=1; j<table.rows.length; j++) {	
		var row_index;
		
		if (sort_direction == 1)
			row_index = smallest_entry(table, j, column_index);
		else
			row_index = biggest_entry(table, j, column_index);
		

		if (row_index > j) {
			var text = table.rows[row_index].innerHTML;
			table.deleteRow(row_index);
			var new_row = table.insertRow(j);
			new_row.innerHTML = text;
		}
	}

	if (sort_direction == 0)
		sort_direction = 1;
	else
		sort_direction = 0;

			//z = sta.getElementsByTagName("macaddr")[0].firstChild.nodeValue;

	//for (i=1; i<table.rows.length; i++) {
	//	var cell = table.rows[i].cells[column_index].innerHTML;
	//	list[cell] = cell;
	//}
	//item = document.createElement("div");
	//item.className = "dropdown";
	//var foo = "";
	//for (x in list)
	//	foo = foo + x + " ";
	//item.innerHTML = foo;
	//node.appendChild(item);

}
