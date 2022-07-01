
"use strict";

var ejs = require("ejs");
var fs = require("fs");
var http = require("http");
var https = require("https");
var querystring = require("querystring");
var url = require("url");

var config = require("../config");
var httpConstants = require("../http-constants");
var patterns = require("./patterns");


// Khởi tạo Server
var server = http.createServer();

server.listen(config.proxyPort, handleListening);

// Xử lý yêu cầu request gửi đến
server.on("request", handleRequest);

function handleListening() {
	console.log("Khoi tao proxy, lang nghe cong: " + config.proxyPort);
}

/**
 * @param proxiedRequest
 * @param proxiedResponse
 */
function handleRequest(proxiedRequest, proxiedResponse) {
	console.log("Xu ly yeu cau: ");
	
	var requestBody = "";

	function handleRequestData(data) {
		requestBody += data;
	}

	function handleRequestEnd() {

		function handleResponse(rawResponse) {
			proxiedResponse.writeHead(rawResponse.statusCode, rawResponse.headers);
			rawResponse.pipe(proxiedResponse);
		}

		function handleRawRequest() {
			var requestOptions = getRawRequestOptions(proxiedRequest);

			console.log(`requestOptions = ${JSON.stringify(requestOptions)}`);

			var request = null;
			if (requestOptions.port === 443 || config.forceSSL)
				request = https.request(requestOptions, handleResponse);
			else
				request = http.request(requestOptions, handleResponse);

			request.on("error", function(error) {
				if (httpConstants.errorCodes.UNRESOLVED_HOST === error.code) {
					proxiedResponse.write("Khong tim thay may chu tai: " + requestOptions.hostname);
				}
				else {
					console.log(error);
					proxiedResponse.write("Khong tim thay may chu!");
				}
				proxiedResponse.end(); 
			});
			request.write(requestBody);
			request.end();
		}

		// Quét dữ liệu gửi đi từ Clients với Regex SQL injection
		var blockedReason = scanParameters(getProxiedRequestParams(proxiedRequest, requestBody));
		if(blockedReason) {
			proxiedResponse.statusCode = httpConstants.responseCodes.HTTP_SUCCESS_OK;

			if(proxiedRequest.method === "GET") {
				proxiedResponse.setHeader(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT);
				proxiedResponse.write(renderBlockedHTML(blockedReason));
			}
			else {
				proxiedResponse.setHeader(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON);
				proxiedResponse.write(renderBlockedJSON(blockedReason));
			}

			proxiedResponse.end();
		} else {
			handleRawRequest();
		}
	}
	proxiedRequest.on("data", handleRequestData);
	proxiedRequest.on("end", handleRequestEnd);
}


/**
 * @param proxiedRequest
 * @param requestBody
 * @returns {{}}
 */
// Lấy dữ liệu gửi đi từ Clients
function getProxiedRequestParams(proxiedRequest, requestBody) {

	var requestParams = {};
	var key = "";

	var urlParts = url.parse(proxiedRequest.url, true);
	if(urlParts.query !== null) {
		for(key in urlParts.query) {
			// console.log(`key= ${JSON.stringify(key)}`);
		let	OBJjavascript = JSON.parse(JSON.stringify(urlParts.query));
			// console.log(`OBJjavascript= ${JSON.stringify(OBJjavascript)}`);
			if(OBJjavascript.hasOwnProperty(key)) {
				requestParams["query."+key] = OBJjavascript[key];
			}
		}
		// console.log(`requestParams = ${JSON.stringify(requestParams)}`);
	}

	if(requestBody !== null) {
		var body = querystring.parse(requestBody);
		// console.log(`body= ${JSON.stringify(body)}`);
		for(key in body) {
			let	OBJjavascript = JSON.parse(JSON.stringify(body));
			// console.log(`key= ${JSON.stringify(key)}`);
			if(OBJjavascript.hasOwnProperty(key))
				requestParams["body."+key] = body[key];
		}
				// console.log(`requestParams = ${JSON.stringify(requestParams)}`);
	}
	var urlAttributes = urlParts.pathname.split("/");
	for(var index=0; index<urlAttributes.length; index++) {
		if(urlAttributes[index].length > 0)
			requestParams["pathname."+index] = decodeURIComponent(urlAttributes[index]);
	}
	return requestParams;
}


/**
 * @param proxiedRequest
 * @returns {{hostname: string, port: number, method: (*|chainableBehavior.method|string|method|parserOnHeadersComplete.incoming.method|IncomingMessage.method), path: string, headers: {}}}
 */
function getRawRequestOptions(proxiedRequest) {

	var relativePath = proxiedRequest.url;
	// console.log(`relativePath = ${JSON.stringify(relativePath)}`)
	if(proxiedRequest.url.substring(0, 1) === "/")
		relativePath = relativePath.substring(1, relativePath.length);
	var rawRequestHeaders = {};
	if(typeof proxiedRequest.headers !== "undefined" && proxiedRequest.headers !== null) {
		rawRequestHeaders = Object.assign({}, proxiedRequest.headers);
		delete rawRequestHeaders.host;
	}
	var requestOptions = {
		"hostname": config.targetHost,
		"port": config.targetPort,
		"method": proxiedRequest.method,
		"path": "/" + relativePath,
		"headers": rawRequestHeaders
	};

	return requestOptions;
}


/**
 * @param parameters
 * @returns {boolean}
 */
function scanParameters(parameters) {
	if(parameters !== null) {
		for(var key in parameters) {
			if (parameters.hasOwnProperty(key)) {
				for (var index = 0; index < patterns.length; index++) {
					if (patterns[index].regex.test(parameters[key])) {
						console.log("Xac dinh loi: " + patterns[index].description);
						return patterns[index].description;
					}
				}
			}
		}
	}
	return null;
}

/**
 * @param description
 * @returns {String} 
 */
function renderBlockedHTML(description) {
	var template = fs.readFileSync(__dirname + "/view/index.html", "utf8");
	var renderData = {
		description: description
	};
	return ejs.render(template, renderData);
}

/**
 * @param description
 * @returns {String}
 */
function renderBlockedJSON(description) {
	var responseBody = {
		success: false,
		message: description
	};
	return JSON.stringify(responseBody);
}
