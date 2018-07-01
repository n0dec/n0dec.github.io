function raw_to_rule() {
	var rules = {};
	var raw = document.getElementById("raw").value;

	var raw_split = raw.split('\n\n');

	for(var n = 0; n < raw_split.length; n++){
		raw_split2 = raw_split[n].split('\n');
		iter = n + 1
		rules['rule' + iter] = {}
		rules['rule' + iter].enabled = true;
		rules['rule' + iter].source = "Sysmon";
		rules['rule' + iter].category = raw_split2[0].slice(0, -1);
		rules['rule' + iter].description = 'Description for rule' + iter;
		rules['rule' + iter].payload = {}

		for (var i = 1; i < raw_split2.length; i++) {
			var f_split = raw_split2[i].split(': ')
			rules['rule' + iter].payload[f_split[0]] = f_split[1]
		}
	}
	var json = JSON.stringify(rules, null, "\t");

	document.getElementById("rule").innerHTML = "\"rules\": " + json;
}


function num_rules(array){

		var result = [];

		for (var i = 0; i < array.length; i++) {
			if(array[i] == '')
				result.push(i);
		}

		return result;
}
