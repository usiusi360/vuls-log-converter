#!/usr/bin/env node

'use strict';

const fs = require('fs');
const elasticsearch = require('elasticsearch');
const json2csv = require('json2csv');
const dateFormat = require('dateformat');
const argv = require('argv');

const esIndexName = "vuls_index";
const esTypeName = "vuls_type";
let fields = [
    "ScannedAt",
    "ServerName",
    "Family",
    "Release",
    "Container_Name",
    "Container_ContainerID",
    "Platform_Name",
    "Platform_InstanceID",
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
    "NVD_Summary",
    "NVD_PublishedDate",
    "NVD_LastModifiedDate",
    "JVN_Score",
    "JVN_Severity",
    "JVN_AcessVector",
    "JVN_AccessComplexity",
    "JVN_Authentication",
    "JVN_ConfidentialityImpact",
    "JVN_IntegrityImpact",
    "JVN_AvailabilityImpact",
    "JVN_Title",
    "JVN_Summary",
    "JVN_JvnLink",
    "JVN_PublishedDate",
    "JVN_LastModifiedDate",
    "JVN_ID"
];


argv.option([{
    name: 'type',
    short: 't',
    type: 'string',
    description: 'Output as CSV or JSON for ElasticSearch',
    example: '[csv|els]'
}, {
    name: 'input',
    short: 'i',
    type: 'path',
    description: 'vuls result dir',
    example: '--input=/opt/vuls/results/current/ or -i /opt/vuls/results/current/'
}, {
    name: 'output',
    short: 'o',
    type: 'string',
    description: 'output file name',
    example: '--output=./output.csv or -o ./output.csv'
}, {
    name: 'esEndPoint',
    short: 'e',
    type: 'string',
    description: 'ElasticSearch EndPoint',
    example: '--esEndPoint=https://hogehoge.com/ or -e https://hogehoge.com/'
}, {
    name: 'config',
    short: 'c',
    type: 'string',
    description: 'config file [option]',
    example: '--config=./config.json or -c ./config.json'
}]);

const args = argv.run().options;
const type = args.type;
const input = args.input;
const output = args.output;
const esEndPoint = args.esEndPoint;
const config = args.config

//==============

let getFileList = function(path) {
    return new Promise(function(resolve, reject) {

        fs.readdir(path, function(err, files) {
            if (err) {
                reject(new Error("Access denied or File not found [" + path + "]"));
                return;
            }

            let fileList = [];
            files.filter(function(file) {
                return fs.statSync(path + "/" + file).isFile() && /.*\.json$/.test(file);
            }).forEach(function(file) {
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

let getPkgObj = function(target, json) {
    let result = [];

    if ( json[target] === null ) {
        console.log(`[ERROR] : target data not found.[${target}]  Please check after running "vuls report -format-json".`);
	return;
    }

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
            let targetObj = {};

            if (fields.indexOf("ScannedAt") >= 0) { targetObj["ScannedAt"] = getFormatDate(json.ScannedAt) };
            if (fields.indexOf("ServerName") >= 0) { targetObj["ServerName"] = json.ServerName };
            if (fields.indexOf("Family") >= 0) { targetObj["Family"] = json.Family };
            if (fields.indexOf("Release") >= 0) { targetObj["Release"] = json.Release };
            if (fields.indexOf("Container_Name") >= 0) { targetObj["Container_Name"] = json.Container.Name };
            if (fields.indexOf("Container_ContainerID") >= 0) { targetObj["Container_ContainerID"] = json.Container.ContainerID };
            if (fields.indexOf("Platform_Name") >= 0) { targetObj["Platform_Name"] = json.Platform.Name };
            if (fields.indexOf("Platform_InstanceID") >= 0) { targetObj["Platform_InstanceID"] = json.Platform.InstanceID };
            if (fields.indexOf("CveID") >= 0) { targetObj["CveID"] = targetVals.CveDetail.CveID };
            if (fields.indexOf("Packages_Name") >= 0) { targetObj["Packages_Name"] = targetPkg.Name };

            if (targetVals.CveDetail.Nvd.Score !== 0) {
                if (fields.indexOf("NVD_Score") >= 0) { targetObj["NVD_Score"] = targetVals.CveDetail.Nvd.Score };
                if (fields.indexOf("NVD_Severity") >= 0) { targetObj["NVD_Severity"] = getSeverity(targetVals.CveDetail.Nvd.Score) };
                if (fields.indexOf("NVD_AcessVector") >= 0) { targetObj["NVD_AcessVector"] = targetVals.CveDetail.Nvd.Score };
                if (fields.indexOf("NVD_AccessComplexity") >= 0) { targetObj["NVD_AccessComplexity"] = targetVals.CveDetail.Nvd.AccessComplexity };
                if (fields.indexOf("NVD_Authentication") >= 0) { targetObj["NVD_Authentication"] = targetVals.CveDetail.Nvd.Authentication };
                if (fields.indexOf("NVD_ConfidentialityImpact") >= 0) { targetObj["NVD_ConfidentialityImpact"] = targetVals.CveDetail.Nvd.ConfidentialityImpact };
                if (fields.indexOf("NVD_IntegrityImpact") >= 0) { targetObj["NVD_IntegrityImpact"] = targetVals.CveDetail.Nvd.IntegrityImpact };
                if (fields.indexOf("NVD_AvailabilityImpact") >= 0) { targetObj["NVD_AvailabilityImpact"] = targetVals.CveDetail.Nvd.AvailabilityImpact };
                if (fields.indexOf("NVD_CweID") >= 0) { targetObj["NVD_CweID"] = targetVals.CveDetail.Nvd.CweID };
                if (fields.indexOf("NVD_Summary") >= 0) { targetObj["NVD_Summary"] = targetVals.CveDetail.Nvd.Summary };
                if (fields.indexOf("NVD_PublishedDate") >= 0) { targetObj["NVD_PublishedDate"] = getFormatDate(targetVals.CveDetail.Nvd.PublishedDate) };
                if (fields.indexOf("NVD_LastModifiedDate") >= 0) { targetObj["NVD_LastModifiedDate"] = getFormatDate(targetVals.CveDetail.Nvd.LastModifiedDate) };
            }

            if (targetVals.CveDetail.Jvn.Score !== 0) {
                if (fields.indexOf("JVN_Score") >= 0) { targetObj["JVN_Score"] = targetVals.CveDetail.Jvn.Score };
                if (fields.indexOf("JVN_Severity") >= 0) { targetObj["JVN_Severity"] = targetVals.CveDetail.Jvn.Severity };
                let arrayVector = getSplitArray(targetVals.CveDetail.Jvn.Vector);
                if (fields.indexOf("JVN_AcessVector") >= 0) { targetObj["JVN_AcessVector"] = getVector.jvn(arrayVector[0]) };
                if (fields.indexOf("JVN_AccessComplexity") >= 0) { targetObj["JVN_AccessComplexity"] = getVector.jvn(arrayVector[1]) };
                if (fields.indexOf("JVN_Authentication") >= 0) { targetObj["JVN_Authentication"] = getVector.jvn(arrayVector[2]) };
                if (fields.indexOf("JVN_ConfidentialityImpact") >= 0) { targetObj["JVN_ConfidentialityImpact"] = getVector.jvn(arrayVector[3]) };
                if (fields.indexOf("JVN_IntegrityImpact") >= 0) { targetObj["JVN_IntegrityImpact"] = getVector.jvn(arrayVector[4]) };
                if (fields.indexOf("JVN_AvailabilityImpact") >= 0) { targetObj["JVN_AvailabilityImpact"] = getVector.jvn(arrayVector[5]) };
                if (fields.indexOf("JVN_ID") >= 0) { targetObj["JVN_ID"] = targetVals.CveDetail.Jvn.JvnID };
                if (fields.indexOf("JVN_Title") >= 0) { targetObj["JVN_Title"] = targetVals.CveDetail.Jvn.Title };
                if (fields.indexOf("JVN_Summary") >= 0) { targetObj["JVN_Summary"] = targetVals.CveDetail.Jvn.Summary };
                if (fields.indexOf("JVN_JvnLink") >= 0) { targetObj["JVN_JvnLink"] = targetVals.CveDetail.Jvn.JvnLink };
                if (fields.indexOf("JVN_PublishedDate") >= 0) { targetObj["JVN_PublishedDate"] = getFormatDate(targetVals.CveDetail.Jvn.PublishedDate) };
                if (fields.indexOf("JVN_LastModifiedDate") >= 0) { targetObj["JVN_LastModifiedDate"] = getFormatDate(targetVals.CveDetail.Jvn.LastModifiedDate) };
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
        maxSockets: 3,
        requestTimeout: 300000,
        deadTimeout: 600000,
        apiVersion: '2.4'
    });

    client.bulk({
        index: esIndexName,
        type: esTypeName,
        body: data
    }).then(function(resp) {
        console.log(resp);
    }, function(err) {
        console.trace(err.message);
    });

};

let createEsPostData = function(data) {
    let result = [];
    let index = { index: {} };

    data.forEach(function(value, i) {
        result.push(index);
        result.push(value);
    });

    return result;
};

let createCsvData = function(data, i) {
    let result;
    if (i === 0) {
        result = json2csv({ data: data, fields: fields, hasCSVColumnTitle: true });
    } else {

        result = json2csv({ data: data, fields: fields, hasCSVColumnTitle: false });
    }
    result = result + "\n";
    return result;
};

let outputData = function(data) {
    fs.appendFileSync(output, data, 'utf8', function(err) {
        console.log(err);
    });
};

let getSplitArray = function(full_vector) {
    return full_vector.replace(/\(|\)/g, '').split("/");
};

let getFormatDate = function(date) {
    return dateFormat(date, "yyyy/mm/dd HH:MM:ss")
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

    jvn: function(vector) {
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

(function() {
    if (type !== "csv" && type !== "els") {
        console.error("[ERROR] : unknown type.");
        return;
    }

    if (input === undefined) {
        console.error("[ERROR] : input dir not found.");
        return;
    }

    if (type === "csv" && output === undefined) {
        console.error("[ERROR] : output file not found.");
        return;
    }

    if (type === "els" && esEndPoint === undefined) {
        console.error("[ERROR] : esEndPoint not found.");
        return;
    }

   if ( config !== undefined) {
        fields = JSON.parse(fs.readFileSync(config, 'utf8'));
   }

    getFileList(input).then(function(fileList) {
        console.log("[INFO] : Convert start.");

        let num = 0;
        let tmp_array = [];
        fileList.forEach(function(path, i) {
            let data = getFlatObj(path);
            if (type === "csv") {
                outputData(createCsvData(data, i));
            } else if (type === "els") {
                doEsPostData(createEsPostData(data))

                // tmp_array.push(createEsPostData(data));
                // if (num < 100) {
                //   num++;
                // } else {
                //   doEsPostData(tmp_array);
                //   console.log(tmp_array);
                //   num = 0;
                //   tmp_array = [];
                // }
            }

        });
        console.log("[INFO] : Convert success.");

    }).catch(function(error) {
        console.error(error);
    });
}());
