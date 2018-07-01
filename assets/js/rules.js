function raw_to_rule() {
	var rule = {};
	var raw = document.getElementById("raw").value;

	var raw_split = raw.split('\n');

	rule.enabled = true;
	rule.source = "Sysmon";
	rule.category = raw_split[0].slice(0, -1);
	rule.description = 'newValue';
	rule.payload = {}

	for (var i = 1; i < raw_split.length; i++) {
		var f_split = raw_split[i].split(': ')
		rule.payload[f_split[0]] = f_split[1]
	}
	var json = JSON.stringify(rule, null, "\t");

	document.getElementById("rule").innerHTML = json;
}
