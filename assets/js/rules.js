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
				rules['rule' + rule_n].payload[f_split[0]] = f_split[1]
			}
		}
	}
	json_rules(rules);
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
				rules['rule' + rule_n].payload[f_split[0]] = f_split[1]
			}
		}
	}
	json_rules(rules);
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
			return;
		}

		// console.log();
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
	json_rules(rules);
}

function json_rules(rules){
	var set = {}

	set['name'] = "Rule set name";
	set['version'] = "0.1";
	set['author'] = "n0dec.github.io/#rules";
	set['description'] = "Description for rule set.";
	set.rules = rules;

	var json = JSON.stringify(set, null, "\t");
	document.getElementById("rule").innerHTML = json;
}

function rule_format() {
	var data = document.getElementById("raw").value;
	var first_line = data.split('\n')[0];

	if (first_line.substring(0, 6) == '<Event'){
		xml_to_rule(data);
	} else if ((first_line.indexOf(':') != -1) && (first_line.indexOf('[') == -1)) {
		format_to_rule(data);
	} else if (first_line.substring(0, 6) == 'Event[') {
		text_to_rule(data);
	} else {
		console.log('format not recognized');
	}
}
