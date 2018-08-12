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
				if (f_split[1] == null){
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
				if (f_split[1] == null){
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
	document.getElementById("rule").innerHTML = json;
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
		document.getElementById("rule").innerHTML = "Invalid event format!";
	}

}

function to_graph(){
	var data = document.getElementById("raw").value;
	var first_line = data.split('\n')[0];

	var rules = [];

	if (first_line.substring(0, 6) == '<Event'){
		rules = xml_to_rule(data);
	} else if ((first_line.indexOf(':') != -1) && (first_line.indexOf('[') == -1)) {
		rules = format_to_rule(data);
	} else if (first_line.substring(0, 6) == 'Event[') {
		rules = text_to_rule(data);
	} else {
		document.getElementById("raw").innerHTML = "Invalid event format!";
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
			tooltip = this.data('event_category') + "<br>";
			var data = this.data('event_data');
			for(var n in data){
				tooltip += data[n][0] + ": " + data[n][1] + "<br>";
			}
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
