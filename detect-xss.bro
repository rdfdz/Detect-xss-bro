##! XSS attack detection in HTTP.

@load ./decode

module XSS;

export {

	redef enum Log::ID += {LOG};

	type Info: record {

		# Timestamp for when the request happened.
		ts:	time				&log;
		# The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id     		&log;
		## The transport layer protocol of the connection.
		proto: transport_proto	&log;
		# Verb used in the HTTP request (GET, POST, HEAD, etc.).
		method: string			&log;
		# The injection produced
		xss_payload: string		&log;
	};

	const match_xss_reflected =

	# A script tag can be used to define inline script, or load a script file from another location.
	/(<)(\/)*script+.*?(>)/

	# Check inside an HTML comment.(-->).*(<!--)) opossite. example --><script>alert("I just escaped the HTML comment")</script><!--
	| /((<!--).*?(-->)|(-->).*(<!--))/

	# A link can be made to run javascript by using javascript: in the URL. Can be encode.
	| /(javascript:|vbscript:|livescript:)/

	# Load an external CSS stylesheet
	| /(@import)/

	# Javascript events
	| /(fscommand|onabort|onactivate|onafterprint|onafterupdate|onbeforeactivate|onbeforecopy|onbeforecut|onbeforedeactivate|onbeforeeditfocus|onbeforepaste|onbeforeprint|onbeforeunload|onbeforeupdate|onbegin|onblur|onbounce|oncellchange|onchange|onclick|oncontextmenu|oncontrolselect|oncopy|oncut|ondataavailable|ondatasetchanged|ondatasetcomplete|ondblclick|ondeactivate|ondrag|ondragend|ondragleave|ondragenter|ondragover|ondragdrop|ondragstart|ondrop|onend|onerror|onerrorupdate|onfilterchange|onfinish|onfocus|onfocusin|onfocusout|onhashchange|onhelp|oninput|onkeydown|onkeypress|onkeyup|onlayoutcomplete|onload|onlosecapture|onmediacomplete|onmediaerror|onmessage|onmousedown|onmouseenter|onmouseleave|onmousemove|onmouseout|onmouseover|onmouseup|onmousewheel|onmove|onmoveend|onmovestart|onoffline|ononline|onoutofsync|onpaste|onpause|onpopstate|onprogress|onpropertychange|onreadystatechange|onredo|onrepeat|onreset|onresize|onresizeend|onresizestart|onresume|onreverse|onrowsenter|onrowexit|onrowdelete|onrowinserted|onscroll|onseek|onselect|onselectionchange|onselectstart|onstart|onstop|onstorage|onsyncrestored|onsubmit|ontimeerror|ontrackchange|onundo|onunload|onurlflip|seeksegmenttime|onpageshow)\s*=[^<]*/

	# BASE tag URL
	| /<base.+?href.+?>/

	# HTML breaking
	| /#.+?\)["\s]*>/

	# Self-contained payload
	| /with\s*\(.+?(\()/

	# Common JavaScript injection points (forms)
	| /<(form|button|input|keygen|textarea|select|option)/

	# Conditional compilation token
	| /@(cc_on|set)/

	# base64 usage
	| /src=[^<]*base64[^<]*(\>)/

	# js in the style attribute
	| /style=[^<]*((expression\s*?\([^<]*?\))|(behavior\s*:))[^<]*/

	# Data URI scheme base64
	| /data:.*?base64.*?/

	# detect mocha in tag img
	| /img\s*src=.*?mocha/

	&redef;

}



event bro_init() &priority=5 {

	Log::create_stream(XSS::LOG, [$columns=Info, $path="xss"]);
}


# Generated for HTTP requests. Bro supports persistent and pipelined HTTP
# sessions and raises corresponding events as it parses client/server
# dialogues. This event is generated as soon as a request's initial line has
# been parsed, and before any :bro:id:`http_header` events are raised.
#
# c: The connection.
#
# method: The HTTP method extracted from the request (e.g., ``GET``, ``POST``).
#
# original_URI: The unprocessed URI as specified in the request.
#
# unescaped_URI: The URI with all percent-encodings decoded.
#
# version: The version number specified in the request (e.g., ``1.1``).
#
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {

	local xss_payload = sanitize(unescaped_URI);
	
	if ( match_xss_reflected in xss_payload) {
		
	
		local rec: XSS::Info = [
			$ts=network_time(),
			$id=c$id,
			$proto=get_port_transport_proto(c$id$resp_p),
			$method=method,
			$xss_payload=xss_payload
		];

		Log::write(XSS::LOG, rec);
	}
}
