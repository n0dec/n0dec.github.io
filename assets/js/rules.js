function format_to_rule(data) {
	rules = {};
	var raw_split = data.split('\n\n');
	for(var n = 0; n < raw_split.length; n++){
		raw_split2 = raw_split[n].split('\n');
		if(raw_split2 != ''){
			rule_n = n + 1
			rules['rule' + rule_n] = {}
			rules['rule' + rule_n].enabled = true;
			rules['rule' + rule_n].source = "Sysmon";
			rules['rule' + rule_n].category = raw_split2[0].slice(0, -1);
			rules['rule' + rule_n].description = 'Description for rule' + rule_n;
			rules['rule' + rule_n].payload = {}

			for (var i = 1; i < raw_split2.length; i++) {
				var f_split = raw_split2[i].split(': ')
				if (f_split[1] == null && f_split[0] != ""){
					f_split[0] = f_split[0].replace(":","");
					f_split[1] = "";
				}
				rules['rule' + rule_n].payload[f_split[0]] = f_split[1]
			}
		}
	}
	return rules;
}

function text_to_rule(data){
	rules = {};
	var raw_split = data.split('\n\n');
	for(var n = 0; n < raw_split.length; n++){
		raw_split2 = raw_split[n].split('\n');
		if(raw_split2 != ''){
			rule_n = n + 1
			rules['rule' + rule_n] = {}
			rules['rule' + rule_n].enabled = true;
			rules['rule' + rule_n].source = "Sysmon";
			rules['rule' + rule_n].category = raw_split2[13].slice(0, -1);
			rules['rule' + rule_n].description = 'Description for rule' + rule_n;
			rules['rule' + rule_n].payload = {}

			for (var i = 14; i < raw_split2.length; i++) {
				var f_split = raw_split2[i].split(': ')
				if (f_split[1] == null && f_split[0] != ""){
					f_split[0] = f_split[0].replace(":","");
					f_split[1] = "";
				}
				rules['rule' + rule_n].payload[f_split[0]] = f_split[1]
			}
		}
	}
	return rules;
}

function xml_to_rule(data){
	rules = {};
	var raw_split = data.split('\n');
	parser = new DOMParser();
	for(var n = 0; n < raw_split.length; n++) {
		var xmlDoc = parser.parseFromString(raw_split[n], "text/xml");
		try {
			var nodes = xmlDoc.getElementsByTagName("EventData")[0].childNodes;
		}
		catch(err) {
			console.log("Error: Invalid XML object");
			continue;
		}
		rule_n = n + 1
		rules['rule' + rule_n] = {}
		rules['rule' + rule_n].enabled = true;
		rules['rule' + rule_n].source = "Sysmon";
		rules['rule' + rule_n].category = category[xmlDoc.getElementsByTagName("System")[0].childNodes[1].textContent];
		rules['rule' + rule_n].description = 'Description for rule' + rule_n;
		rules['rule' + rule_n].payload = {}
		for (var i = 0; i < nodes.length; i++){
			rules['rule' + rule_n].payload[nodes[i].getAttribute("Name")] = nodes[i].textContent;
		}
	}
	return rules;
}

function json_rules(rules){
	var set = {}

	set['name'] = "Rule set name";
	set['version'] = "0.1";
	set['author'] = "https://n0dec.github.io/#rules";
	set['description'] = "Description for rule set.";
	set.rules = rules;

	var json = JSON.stringify(set, null, "\t");
	document.getElementById("rule").value = json;
}

function rule_format() {
	var data = document.getElementById("raw").value;
	var first_line = data.split('\n')[0];

	if (first_line.substring(0, 6) == '<Event'){
		json_rules(xml_to_rule(data));
	} else if ((first_line.indexOf(':') != -1) && (first_line.indexOf('[') == -1)) {
		json_rules(format_to_rule(data));
	} else if (first_line.substring(0, 6) == 'Event[') {
		json_rules(text_to_rule(data));
	} else {
		document.getElementById("rule").value = "Invalid event format!";
	}

}

function to_graph(){
	var data = document.getElementById("raw").value;
	var first_line = data.split('\n')[0];

	var rules = [];
	
	try {
		var json = JSON.parse(data);
		rules = json.rules;
	} catch(e) {
		if (first_line.substring(0, 6) == '<Event'){
			rules = xml_to_rule(data);
		} else if ((first_line.indexOf(':') != -1) && (first_line.indexOf('[') == -1)) {
			rules = format_to_rule(data);
		} else if (first_line.substring(0, 6) == 'Event[') {
			rules = text_to_rule(data);
		} else {
			document.getElementById("raw").value = "Invalid event format!";
		}
	}

	var nodes = get_nodes(rules);

	var print_elements = [];

	for (var n in rules){
		var node1 = [];
		var node2 = [];
		var edge = [];

		switch(rules[n].category) {
			case "Process Create":
				node1 = [rules[n].payload['ProcessId'], rules[n].payload['Image']];
				node2 = [rules[n].payload['ParentProcessId'], rules[n].payload['ParentImage']];
				edge = [rules[n].payload['ProcessId'], rules[n].payload['ParentProcessId']];
				print_elements.push({ data: {id: node1[0], label: node1[1].replace(/^.*[\\]/, ''), weight: get_weight(nodes, node1), event_category: rules[n].category, event_data: [["User", rules[n].payload["User"]], ["ProcessId", rules[n].payload["ProcessId"]], ["Image", rules[n].payload["Image"]], ["CommandLine", rules[n].payload["CommandLine"]]]} });
				print_elements.push({ data: {id: node2[0], label: node2[1].replace(/^.*[\\]/, ''), weight: get_weight(nodes, node2), event_category: rules[n].category, event_data: [["ProcessId", rules[n].payload["ParentProcessId"]], ["Image", rules[n].payload["ParentImage"]], ["CommandLine", rules[n].payload["ParentCommandLine"]]]} });
				print_elements.push({ data: {source: edge[1], target: edge[0]} });
				break;
			case "Network connection detected":
				node1 = [rules[n].payload['ProcessId'], rules[n].payload['Image']];
				node2 = [rules[n].payload['DestinationIp'], rules[n].payload['DestinationIp']];
				edge = [rules[n].payload['ProcessId'], rules[n].payload['DestinationIp']];
				print_elements.push({ data: {id: node1[0], label: node1[1].replace(/^.*[\\]/, ''), weight: get_weight(nodes, node1)} });
				print_elements.push({ data: {id: node2[0], label: node2[1], weight: get_weight(nodes, node2), event_category: rules[n].category, event_data: [["User", rules[n].payload["User"]], ["ProcessId", rules[n].payload["ProcessId"]], ["Image", rules[n].payload["Image"]], ["Protocol", rules[n].payload["Protocol"]], ["DestinationPort", rules[n].payload["DestinationPort"]]]} });
				print_elements.push({ data: {source: edge[0], target: edge[1]} });
				break;
			case "File created":
				node1 = [rules[n].payload['ProcessId'], rules[n].payload['Image']];
				node2 = [rules[n].payload['TargetFilename'], rules[n].payload['TargetFilename']];
				edge = [rules[n].payload['ProcessId'], rules[n].payload['TargetFilename']];
				print_elements.push({ data: {id: node1[0], label: node1[1].replace(/^.*[\\]/, ''), weight: get_weight(nodes, node1)} });
				print_elements.push({ data: {id: node2[0], label: node2[1], weight: get_weight(nodes, node2), event_category: rules[n].category, event_data: [["ProcessId", rules[n].payload["ProcessId"]], ["Image", rules[n].payload["Image"]], ["TargetFilename", rules[n].payload["TargetFilename"]]]} });
				print_elements.push({ data: {source: edge[0], target: edge[1]} });
				break;
			default:
				console.log(rules[n].category);
		}
	}

	var cy = cytoscape({
		container: document.getElementById('graph'),
		elements: print_elements,
		style: cytoscape.stylesheet()
			.selector('node')
				.css({
					'background-color': 'mapData(weight, 0, 6, #0288D1, #0277BD)',
					'width': 'mapData(weight, 0, 15, 10, 50)',
					'height': 'mapData(weight, 0, 15, 10, 50)',
					'label': 'data(label)',
					'color': 'rgba(27, 31, 34)',
					'font-family': 'Consolas, monaco, monospace',
					'font-size': 14
				})
			.selector('edge')
				.css({
					'width': 2,
					'opacity': 0.25,
					'line-color': '#78909C',
					'curve-style': 'bezier',
					'control-point-distance': 0
				})
			.selector('node:active')
				.css({
					'overlay-padding': 0,
					'overlay-opacity': 0,
					'width': 'mapData(weight, 0, 15, 30, 70)',
					'height': 'mapData(weight, 0, 15, 30, 70)',
					'background-color': 'mapData(weight, 0, 15, #0288D1, #0277BD)',
					'background-opacity': 0.5
				})
			.selector('edge:active')
				.css({
					'overlay-padding': 0,
					'overlay-opacity': 0
				})
			.selector('node:parent')
				.css({
					'background-color': 'black'
				})
			.selector(':selected')
				.css({
					'background-color': 'mapData(weight, 0, 15, #0288D1, #0277BD)'
				}),
		layout: {
			name: 'cose'
		}
	});


	cy.elements('node').qtip({
		content: function() {
			tooltip = "<textarea class=\"qtip-text\" spellcheck=\"false\">" + this.data('event_category') + "\n";
			var data = this.data('event_data');
			for(var n in data){
				tooltip += data[n][0] + ": " + data[n][1] + "\n";
			}
			tooltip += "</textarea>"
			return tooltip;
		}
	});
}

function get_nodes(rules){
	var nodes = [];

	for (var n in rules){
		if (rules[n].payload['ProcessId'] != null && rules[n].payload['Image'] != null)
			nodes.push([rules[n].payload['ProcessId'], rules[n].payload['Image']]);
		if (rules[n].payload['ParentProcessId'] != null && rules[n].payload['ParentImage'] != null)
			nodes.push([rules[n].payload['ParentProcessId'], rules[n].payload['ParentImage']]);
		if (rules[n].payload['SourceProcessId'] != null && rules[n].payload['SourceImage'] != null)
			nodes.push([rules[n].payload['SourceProcessId'], rules[n].payload['SourceImage']]);
	}
	return nodes;
}

function get_weight(data, item){
	var result = 0;

	for(var n in data){
		if(data[n][0] == item[0] && data[n][1] == item[1])
			result += 1;
	}
	return result;
}

function grаph_example(){
	var example = `Process Create:
RuleName:
UtcTime: 2018-08-09 17:52:27.422
ProcessGuid: {365ABB72-7F5B-5B6C-0000-0010E4470200}
ProcessId: 2544
Image: C:\\Windows\\System32\\cmd.exe
FileVersion: 6.1.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows Command Processor
Product: Microsoft� Windows� Operating System
Company: Microsoft Corporation
CommandLine: C:\\Windows\\system32\\cmd.exe /c ""C:\\Users\\IEUser\\Desktop\\sample.cmd" "
CurrentDirectory: C:\\Windows\\system32\\
User: IEWIN7\\IEUser
LogonGuid: {365ABB72-7F55-5B6C-0000-00203DD80000}
LogonId: 0xd83d
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=AD7B9C14083B52BC532FBA5948342B98,SHA256=17F746D82695FA9B35493B41859D39D786D32B23A9D2E00F4011DEC7A02402AE
ParentProcessGuid: {365ABB72-7F5B-5B6C-0000-00108C3E0200}
ParentProcessId: 2512
ParentImage: C:\\Windows\\explorer.exe
ParentCommandLine: C:\\Windows\\explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding

Process Create:
RuleName:
UtcTime: 2018-08-09 17:52:27.452
ProcessGuid: {365ABB72-7F5B-5B6C-0000-00103F4A0200}
ProcessId: 2576
Image: C:\\Windows\\System32\\PING.EXE
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: TCP/IP Ping Command
Product: Microsoft� Windows� Operating System
Company: Microsoft Corporation
CommandLine: ping  8.8.8.8
CurrentDirectory: C:\\Windows\\system32\\
User: IEWIN7\\IEUser
LogonGuid: {365ABB72-7F55-5B6C-0000-00203DD80000}
LogonId: 0xd83d
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=6242E3D67787CCBF4E06AD2982853144,SHA256=4CA10DBA7FF487FDB3F1362A3681D7D929F5AA1262CDFD31B04C30826983FB1D
ParentProcessGuid: {365ABB72-7F5B-5B6C-0000-0010E4470200}
ParentProcessId: 2544
ParentImage: C:\\Windows\\System32\\cmd.exe
ParentCommandLine: C:\\Windows\\system32\\cmd.exe /c ""C:\\Users\\IEUser\\Desktop\\sample.cmd" "

Process Create:
RuleName:
UtcTime: 2018-08-09 17:52:30.617
ProcessGuid: {365ABB72-7F5E-5B6C-0000-001098D10200}
ProcessId: 2896
Image: C:\\Windows\\System32\\timeout.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: timeout - pauses command processing
Product: Microsoft� Windows� Operating System
Company: Microsoft Corporation
CommandLine: timeout  5
CurrentDirectory: C:\\Windows\\system32\\
User: IEWIN7\\IEUser
LogonGuid: {365ABB72-7F55-5B6C-0000-00203DD80000}
LogonId: 0xd83d
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=419A5EF8D76693048E4D6F79A5C875AE,SHA256=C4EFAFC49D46DBA7E89CD94892799C739A3103F724FEC9BE494BF1267FDB059E
ParentProcessGuid: {365ABB72-7F5B-5B6C-0000-0010E4470200}
ParentProcessId: 2544
ParentImage: C:\\Windows\\System32\\cmd.exe
ParentCommandLine: C:\\Windows\\system32\\cmd.exe /c ""C:\\Users\\IEUser\\Desktop\\sample.cmd" "

Process Create:
RuleName:
UtcTime: 2018-08-09 17:52:35.163
ProcessGuid: {365ABB72-7F63-5B6C-0000-0010C6330300}
ProcessId: 3016
Image: C:\\Windows\\System32\\systeminfo.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Displays system information
Product: Microsoft� Windows� Operating System
Company: Microsoft Corporation
CommandLine: systeminfo
CurrentDirectory: C:\\Windows\\system32\\
User: IEWIN7\\IEUser
LogonGuid: {365ABB72-7F55-5B6C-0000-00203DD80000}
LogonId: 0xd83d
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=258B2ED54FC7F74E2FDCCE5861549C1A,SHA256=DCE2C5EA1DA23E63EEFF2620141FBC2CA45FC4A64F40AF89E722F4B5FAFED27C
ParentProcessGuid: {365ABB72-7F5B-5B6C-0000-0010E4470200}
ParentProcessId: 2544
ParentImage: C:\\Windows\\System32\\cmd.exe
ParentCommandLine: C:\\Windows\\system32\\cmd.exe /c ""C:\\Users\\IEUser\\Desktop\\sample.cmd" "

File created:
RuleName:
UtcTime: 2018-08-09 17:52:40.321
ProcessGuid: {365ABB72-7F5B-5B6C-0000-0010E4470200}
ProcessId: 2544
Image: C:\\Windows\\system32\\cmd.exe
TargetFilename: C:\\Users\\IEUser\\AppData\\Local\\Temp\\updates.exe
CreationUtcTime: 2018-08-09 17:52:40.321

Process Create:
RuleName:
UtcTime: 2018-08-09 17:52:40.331
ProcessGuid: {365ABB72-7F68-5B6C-0000-0010721F0400}
ProcessId: 3184
Image: C:\\Windows\\System32\\certutil.exe
FileVersion: 6.1.7601.18151 (win7sp1_gdr.130512-1533)
Description: CertUtil.exe
Product: Microsoft� Windows� Operating System
Company: Microsoft Corporation
CommandLine: certutil.exe  -urlcache -split -f "https://download.sysinternals.com/files/PSTools.zip" %LOCALAPPDATA%\\resources.zip
CurrentDirectory: C:\\Windows\\system32\\
User: IEWIN7\\IEUser
LogonGuid: {365ABB72-7F55-5B6C-0000-00203DD80000}
LogonId: 0xd83d
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=0D52559AEF4AA5EAC82F530617032283,SHA256=48850FB7229D99E48C3A749556684E962587058D612C659C58F8B8DB2D00ABEE
ParentProcessGuid: {365ABB72-7F5B-5B6C-0000-0010E4470200}
ParentProcessId: 2544
ParentImage: C:\\Windows\\System32\\cmd.exe
ParentCommandLine: C:\\Windows\\system32\\cmd.exe /c ""C:\\Users\\IEUser\\Desktop\\sample.cmd" "

Network connection detected:
RuleName:
UtcTime: 2018-08-09 17:52:40.439
ProcessGuid: {365ABB72-7F68-5B6C-0000-0010721F0400}
ProcessId: 3184
Image: C:\\Windows\\System32\\certutil.exe
User: IEWIN7\\IEUser
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 10.0.2.15
SourceHostname: IEWIN7
SourcePort: 49163
SourcePortName:
DestinationIsIpv6: false
DestinationIp: 152.199.19.160
DestinationHostname:
DestinationPort: 443
DestinationPortName: https

File created:
RuleName:
UtcTime: 2018-08-09 17:52:40.784
ProcessGuid: {365ABB72-7F68-5B6C-0000-0010721F0400}
ProcessId: 3184
Image: C:\\Windows\\system32\\certutil.exe
TargetFilename: C:\\Users\\IEUser\\AppData\\Local\\resources.zip
CreationUtcTime: 2018-08-09 17:52:40.784

`;
	document.getElementById("raw").innerHTML = example;
	to_graph();
}
