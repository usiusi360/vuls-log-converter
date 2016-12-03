'use strict';

const fs = require('fs');
const elasticsearch = require('elasticsearch');
const json2csv = require('json2csv');
const dateFormat = require('dateformat');
const argv = require('argv');

argv.option([
        {
		name: 'type',
		short: 't',
		type: 'string',
		description: 'Output as CSV or JSON for ElasticSearch',
		example: '[csv|els]'
	},{
		name: 'input',
		short: 'i',
		type: 'path',
		description: 'vuls result dir',
		example: '--input=/opt/vuls/results/current/ or -i /opt/vuls/results/current/'
	},{
		name: 'output',
		short: 'o',
		type: 'string',
		description: 'output file name',
		example: '--output=./output.csv or -o ./output.csv'
	}
]);

const args = argv.run().options;
const type = args.type;
const input = args.input;
const output = args.output;

if ( type !== "csv" && type !== "els" ) {
	        console.error("[ERROR] : unknown type.");
	        return ;
}

if ( input === undefined ) {
	        console.error("[ERROR] : input dir not found.");
	        return ;
}

if ( output === undefined ) {
	        console.error("[ERROR] : output file not found.");
	        return ;
}

const fields = [
	"ScannedAt",
	"ServerName",
	"Family",
	"Release",
	"Container_Name",
	//"Container_ContainerID",
	"Platform_Name",
	//"Platform_InstanceID",
	"CveID",
	"Packages_Name",
	"NVD_Score",
	"NVD_Severity",
	"NVD_AcessVector",
	"NVD_AccessComplexity",
	"NVD_Authentication",
	"NVD_ConfidentialityImpact",
	"NVD_IntegrityImpact",
	"NVD_AvailabilityImpact",
	"NVD_CweID",
	//"NVD_Summary",
	//"NVD_PublishedDate",
	//"NVD_LastModifiedDate",
	"JVN_Score",
	"JVN_Severity",
	"JVN_AcessVector",
	"JVN_AccessComplexity",
	"JVN_Authentication",
	"JVN_ConfidentialityImpact",
	"JVN_IntegrityImpact",
	"JVN_AvailabilityImpact",
	//"JVN_Title",
	//"JVN_Summary",
	//"JVN_JvnLink",
	//"JVN_PublishedDate",
	//"JVN_LastModifiedDate"
	"JVN_ID"
];

//==============

let getFileList = function(path) { 
	return new Promise(function(resolve, reject){ 

		fs.readdir(path, function(err, files){
			if (err) { 
				reject(new Error("Access denied or File not found [" + path + "]"));
				return;
			}

			let fileList = [];
			files.filter(function(file){
				return fs.statSync(path + "/" + file).isFile() && /.*\.json$/.test(file);
			}).forEach(function (file) {
				fileList.push(path + "/" + file);
			});
			resolve(fileList);
		});
	});
};

let getFlatObj = function(path) {
	let result = [];
	let json = JSON.parse(fs.readFileSync(path, 'utf8'));
	result = result.concat(getPkgObj("KnownCves", json));
	result = result.concat(getPkgObj("UnknownCves", json));
	return result;
};

let getPkgObj = function(target, json){
	let result = [];

	json[target].forEach(function(targetVals, j) {
		let targetPkgs;
		if (targetVals.CpeNames === null) {
			targetPkgs = targetVals.Packages;
		} else {
			if (targetVals.CpeNames.length == 0) {
				targetPkgs = targetVals.Packages;
			} else {
				targetPkgs = targetVals.CpeNames;
			}
		}

		targetPkgs.forEach(function(targetPkg, k) {
			let arrayVector = getSplitArray(targetVals.CveDetail.Jvn.Vector);
			let targetObj = {
				"ScannedAt" : dateFormat(json.ScannedAt, "yyyy/mm/dd HH:MM:ss"),
				"ServerName" : json.ServerName,
				"Family" : json.Family,
				"Release" : json.Release,
				"Container_Name" : json.Container.Name,
				"Container_ContainerID" : json.Container.ContainerID,
				"Platform_Name" : json.Platform.Name,
				"Platform_InstanceID" : json.Platform.InstanceID,
				"CveID" : targetVals.CveDetail.CveID,     
				"Packages_Name" : targetPkg.Name
			};

			if (targetVals.CveDetail.Nvd.Score !== 0) {
				targetObj["NVD_Score"] = targetVals.CveDetail.Nvd.Score;
				targetObj["NVD_Severity"] = getSeverity(targetVals.CveDetail.Nvd.Score);
				targetObj["NVD_AcessVector"] =  targetVals.CveDetail.Nvd.Score;
				targetObj["NVD_AccessComplexity"] = targetVals.CveDetail.Nvd.AccessComplexity;
				targetObj["NVD_Authentication"] = targetVals.CveDetail.Nvd.Authentication;
				targetObj["NVD_ConfidentialityImpact"] =  targetVals.CveDetail.Nvd.ConfidentialityImpact;
				targetObj["NVD_IntegrityImpact"] = targetVals.CveDetail.Nvd.IntegrityImpact;
				targetObj["NVD_AvailabilityImpact"] = targetVals.CveDetail.Nvd.AvailabilityImpact;
				targetObj["NVD_CweID"] = targetVals.CveDetail.Nvd.CweID;
				targetObj["NVD_Summary"] = targetVals.CveDetail.Nvd.Summary;
				targetObj["NVD_PublishedDate"] = targetVals.CveDetail.Nvd.PublishedDate;
				targetObj["NVD_LastModifiedDate"] = targetVals.CveDetail.Nvd.LastModifiedDate;
			}

			if (targetVals.CveDetail.Jvn.Score !== 0) {
				targetObj["JVN_Score"] = targetVals.CveDetail.Jvn.Score;
				targetObj["JVN_Severity"] = targetVals.CveDetail.Jvn.Severity;
				targetObj["JVN_AcessVector"] = getVector.jvn(arrayVector[0]);
				targetObj["JVN_AccessComplexity"] = getVector.jvn(arrayVector[1]);
				targetObj["JVN_Authentication"] = getVector.jvn(arrayVector[2]);
				targetObj["JVN_ConfidentialityImpact"] = getVector.jvn(arrayVector[3]);
				targetObj["JVN_IntegrityImpact"] = getVector.jvn(arrayVector[4]);
				targetObj["JVN_AvailabilityImpact"] = getVector.jvn(arrayVector[5]);
				targetObj["JVN_ID"] = targetVals.CveDetail.Jvn.JvnID;
				targetObj["JVN_Title"] = targetVals.CveDetail.Jvn.Title;
				targetObj["JVN_Summary"] = targetVals.CveDetail.Jvn.Summary;
				targetObj["JVN_JvnLink"] = targetVals.CveDetail.Jvn.JvnLink;
				targetObj["JVN_PublishedDate"] = targetVals.CveDetail.Jvn.PublishedDate;
				targetObj["JVN_LastModifiedDate"] = targetVals.CveDetail.Jvn.LastModifiedDate;
			}

			result.push(targetObj);
		});
	});

	return result;
};

let doEsPostData = function(data) {
	let client = new elasticsearch.Client({
		host: esEndPoint,
		log: 'info',
		apiVersion: '2.4'
	});

	client.bulk({
		index: esIndexName,
		type: esTypeName,
		body: data
	}).then(function (resp) {
		//console.log(resp);
	}, function (err) {
		console.trace(err.message);
	});

};

let createEsPostData = function(data) {
	let result = [];
	let index = { index : {} };

	data.forEach(function(value,i) {
		result.push(index);
		result.push(value);
	});

	return result;
};

let createCsvData = function(data, i) {
	let result;
	if ( i === 0 ) {
		result = json2csv({ data: data, fields: fields, hasCSVColumnTitle: true});
	} else {

		result = json2csv({ data: data, fields: fields, hasCSVColumnTitle: false});
	}
	return result;
};

let outputData = function(data){
	fs.appendFileSync( output, data, 'utf8', function (err) {
		console.log(err);
	});
};

let getSplitArray = function(full_vector) {
	return full_vector.replace(/\(|\)/g, '').split("/");
};


let getSeverity = function(Score) {
	if (Score >= 7.0) {
		return "High";
	} else if ((Score < 7.0) && (Score >= 4.0)) {
		return "Medium";
	} else if ((Score < 4.0)) {
		return "Low";
	}
};

let getVector = {

	jvn : function(vector) {
		let subscore = vector.split(":");

		switch (subscore[0]) {
			case 'AV':
				switch (subscore[1]) {
					case 'L':
						return "LOCAL";
						break;
					case 'A':
						return "ADJACENT_NETWORK";
						break;
					case 'N':
						return "NETWORK";
						break;
				}
			case 'AC':
				switch (subscore[1]) {
					case 'H':
						return "HIGH";
						break;
					case 'M':
						return "MEDIUM";
						break;
					case 'L':
						return "LOW";
						break;
				}
			case 'Au':
				switch (subscore[1]) {
					case 'N':
						return "NONE";
						break;
					case 'S':
						return "SINGLE_INSTANCE";
						break;
					case 'M':
						return "MULTIPLE_INSTANCES";
						break;
				}
			case 'C':
				switch (subscore[1]) {
					case 'N':
						return "NONE";
						break;
					case 'P':
						return "PARTIAL";
						break;
					case 'C':
						return "COMPLETE";
						break;
				}
			case 'I':
				switch (subscore[1]) {
					case 'N':
						return "NONE";
						break;
					case 'P':
						return "PARTIAL";
						break;
					case 'C':
						return "COMPLETE";
						break;
				}
			case 'A':
				switch (subscore[1]) {
					case 'N':
						return "NONE";
						break;
					case 'P':
						return "PARTIAL";
						break;
					case 'C':
						return "COMPLETE";
						break;
				}
		}
	}

};


getFileList(input).then(function(fileList) {

	console.log("[INFO] : Convert start.");
	fileList.forEach(function (path, i ){
		let data = getFlatObj(path);
		if ( type === "csv"){
			outputData(createCsvData(data,i));
		} else {
			outputData(JSON.stringify(createEsPostData(data)));
		}

	});
	console.log("[INFO] : Convert success.");

}).catch(function(error) {
	console.error(error);
});
