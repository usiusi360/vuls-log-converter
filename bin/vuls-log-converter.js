#!/usr/bin/env node

'use strict';

const fs = require('fs');
const elasticsearch = require('elasticsearch');
const json2csv = require('json2csv');
const dateFormat = require('dateformat');
const argv = require('argv');
const _u = require('underscore');

const esIndexName = "vuls_index";
const esTypeName = "vuls_type";
const prioltyFlag = ["jvn", "nvd", "redhat", "ubuntu", "debian", "oracle"];

const fields = [
    "ScannedAt",
    "Platform",
    "Family",
    "Release",
    "ServerName",
    "Container",
    "CveID",
    "DetectionMethod",
    "Packages",
    "PackageVer",
    "NewPackageVer",
    "NotFixedYet",
    "CweID",
    "CVSS Score",
    "CVSS Severity",
    "CVSS (AV)",
    "CVSS (AC)",
    "CVSS (Au)",
    "CVSS (C)",
    "CVSS (I)",
    "CVSS (A)",
    "Summary",
    // "Changelog",
    "Published",
    "LastModified",
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
}]);

const args = argv.run().options;
const type = args.type;
const input = args.input;
const output = args.output;
const esEndPoint = args.esEndPoint;
const config = args.config


const getFileList = function(path) {
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

const getFlatObj = function(targetObj) {
    let result = [];

    if (Object.keys(targetObj.ScannedCves).length === 0) {
        let tmp_result = {
            "ScannedAt": getFormatDate(targetObj.ScannedAt),
            "Family": targetObj.Family,
            "Release": targetObj.Release,
            "CveID": "healthy",
            "DetectionMethod": "healthy",
            "Packages": "healthy",
            "PackageVer": "healthy",
            "NewPackageVer": "healthy",
            "NotFixedYet": "healthy",
            "CweID": "healthy",
            "CVSS Score": "healthy",
            "CVSS Severity": "healthy",
            "CVSS (AV)": "healthy",
            "CVSS (AC)": "healthy",
            "CVSS (Au)": "healthy",
            "CVSS (C)": "healthy",
            "CVSS (I)": "healthy",
            "CVSS (A)": "healthy",
            "Summary": "healthy",
            "Changelog": "healthy",
            "Published": "healthy",
            "LastModified": "healthy",
        };

        if (targetObj.Platform.Name !== "") {
            tmp_result["Platform"] = targetObj.Platform.Name;
        } else {
            tmp_result["Platform"] = "None";
        }

        if (targetObj.RunningKernel.RebootRequired === true) {
            tmp_result["ServerName"] = targetObj.ServerName + " [Reboot Required]";
        } else {
            tmp_result["ServerName"] = targetObj.ServerName;
        }

        if (targetObj.Container.Name !== "") {
            tmp_result["Container"] = targetObj.Container.Name;
        } else {
            tmp_result["Container"] = "None";
        }

        result.push(tmp_result);

    } else {
        _u.each(targetObj.ScannedCves, function(cveidObj, i) {
            let targetNames;
            if (isCheckNull(cveidObj.CpeNames) === false) {
                targetNames = cveidObj.CpeNames;
            } else {
                targetNames = cveidObj.AffectedPackages;
            }

            _u.each(targetNames, function(packs, j) {
                var pkgName, NotFixedYet;
                if (packs.Name === undefined) {
                    pkgName = packs;
                    NotFixedYet = "Unknown";
                } else {
                    pkgName = packs.Name;
                    NotFixedYet = packs.NotFixedYet;
                }

                let pkgInfo = targetObj.Packages[pkgName];
                if (pkgName.indexOf('cpe:/') === -1 && pkgInfo === undefined) {
                    return;
                }

                let tmp_result = {
                    "ScannedAt": getFormatDate(targetObj.ScannedAt),
                    "Family": targetObj.Family,
                    "Release": targetObj.Release,
                    // "CveID": "CHK-cveid-" + cveidObj.CveID,
                    "CveID": cveidObj.CveID,
                    "Packages": pkgName,
                    "NotFixedYet": NotFixedYet,
                };

                if (targetObj.RunningKernel.RebootRequired === true) {
                    tmp_result["ServerName"] = targetObj.ServerName + " [Reboot Required]";
                } else {
                    tmp_result["ServerName"] = targetObj.ServerName;
                }

                if (cveidObj.CveContents.nvd !== undefined) {
                    tmp_result["CweID"] = cveidObj.CveContents.nvd.CweID;
                } else {
                    tmp_result["CweID"] = "None";
                }

                if (targetObj.Platform.Name !== "") {
                    tmp_result["Platform"] = targetObj.Platform.Name;
                } else {
                    tmp_result["Platform"] = "None";
                }

                if (targetObj.Container.Name !== "") {
                    tmp_result["Container"] = targetObj.Container.Name;
                } else {
                    tmp_result["Container"] = "None";
                }

                var DetectionMethod = cveidObj.Confidence.DetectionMethod;
                tmp_result["DetectionMethod"] = DetectionMethod;
                if (DetectionMethod === "ChangelogExactMatch") {
                    tmp_result["Changelog"] = "CHK-changelog-" + cveidObj.CveID + "," + targetObj.ScannedAt + "," + targetObj.ServerName + "," + targetObj.Container.Name + "," + pkgName;
                } else {
                    tmp_result["Changelog"] = "None";
                }

                if (pkgInfo !== undefined) {
                    if (pkgInfo.Version !== "") {
                        tmp_result["PackageVer"] = pkgInfo.Version + "-" + pkgInfo.Release;
                    } else {
                        tmp_result["PackageVer"] = "None";
                    }

                    if (pkgInfo.NewVersion !== "") {
                        tmp_result["NewPackageVer"] = pkgInfo.NewVersion + "-" + pkgInfo.NewRelease;
                    } else {
                        tmp_result["NewPackageVer"] = "None";
                    }
                } else {
                    // ===for cpe
                    tmp_result["PackageVer"] = "Unknown";
                    tmp_result["NewPackageVer"] = "Unknown";
                }


                let getCvss = function(target) {
                    if (cveidObj.CveContents[target] === undefined) {
                        return false;
                    }

                    if (cveidObj.CveContents[target].Cvss2Score === 0 & cveidObj.CveContents[target].Cvss3Score === 0) {
                        return false;
                    }

                    if (cveidObj.CveContents[target].Cvss2Score !== 0) {
                        tmp_result["CVSS Score"] = cveidObj.CveContents[target].Cvss2Score;
                        tmp_result["CVSS Severity"] = getSeverityV2(cveidObj.CveContents[target].Cvss2Score);
                        tmp_result["CVSS Score Type"] = target;
                    } else if (cveidObj.CveContents[target].Cvss3Score !== 0) {
                        tmp_result["CVSS Score"] = cveidObj.CveContents[target].Cvss3Score;
                        tmp_result["CVSS Severity"] = getSeverityV3(cveidObj.CveContents[target].Cvss3Score);
                        tmp_result["CVSS Score Type"] = target + "V3";
                    }

                    tmp_result["Summary"] = cveidObj.CveContents[target].Summary;
                    tmp_result["Published"] = getFormatDate(cveidObj.CveContents[target].Published);
                    tmp_result["LastModified"] = getFormatDate(cveidObj.CveContents[target].LastModified);

                    if (cveidObj.CveContents[target].Cvss2Vector !== "") { //ex) CVE-2016-5483
                        var arrayVector = getSplitArray(cveidObj.CveContents[target].Cvss2Vector);
                        tmp_result["CVSS (AV)"] = getVectorV2.cvss(arrayVector[0])[0];
                        tmp_result["CVSS (AC)"] = getVectorV2.cvss(arrayVector[1])[0];
                        tmp_result["CVSS (Au)"] = getVectorV2.cvss(arrayVector[2])[0];
                        tmp_result["CVSS (C)"] = getVectorV2.cvss(arrayVector[3])[0];
                        tmp_result["CVSS (I)"] = getVectorV2.cvss(arrayVector[4])[0];
                        tmp_result["CVSS (A)"] = getVectorV2.cvss(arrayVector[5])[0];
                    } else {
                        tmp_result["CVSS (AV)"] = "Unknown";
                        tmp_result["CVSS (AC)"] = "Unknown";
                        tmp_result["CVSS (Au)"] = "Unknown";
                        tmp_result["CVSS (C)"] = "Unknown";
                        tmp_result["CVSS (I)"] = "Unknown";
                        tmp_result["CVSS (A)"] = "Unknown";
                    }
                    return true;
                };

                let flag = false;
                prioltyFlag.forEach(function(i_val, i) {
                    if (flag !== true) {
                        flag = getCvss(i_val);
                    }
                });

                if (flag === false) {
                    tmp_result["Summary"] = "Unknown";
                    tmp_result["CVSS Score"] = "Unknown";
                    tmp_result["CVSS Severity"] = "Unknown";
                    tmp_result["CVSS Score Type"] = "Unknown";
                    tmp_result["CVSS (AV)"] = "Unknown";
                    tmp_result["CVSS (AC)"] = "Unknown";
                    tmp_result["CVSS (Au)"] = "Unknown";
                    tmp_result["CVSS (C)"] = "Unknown";
                    tmp_result["CVSS (I)"] = "Unknown";
                    tmp_result["CVSS (A)"] = "Unknown";
                }

                result.push(tmp_result);
            });
        });
    }

    return result;
};

const doEsPostData = function(data) {
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

const createEsPostData = function(data) {
    let result = [];
    let index = { index: {} };

    data.forEach(function(value, i) {
        result.push(index);
        result.push(value);
    });

    return result;
};

const createCsvData = function(data, i) {
    let result;
    if (i === 0) {
        result = json2csv({ data: data, fields: fields, hasCSVColumnTitle: true });
    } else {

        result = json2csv({ data: data, fields: fields, hasCSVColumnTitle: false });
    }
    result = result + "\n";
    return result;
};

const outputData = function(data) {
    fs.appendFileSync(output, data, 'utf8', function(err) {
        console.log(err);
    });
};

const getFormatDate = function(date) {
    return dateFormat(date, "yyyy/mm/dd HH:MM:ss")
};


// ---- copy from https://github.com/usiusi360/vulsrepo/tree/master/dist/js/vulsrepo_common.js
const isCheckNull = function(o) {
    if (o === undefined) {
        return true;
    } else if (o === null) {
        return true;
    } else if (o.length === 0) {
        return true;
    }
    return false;
}

const getSplitArray = function(full_vector) {
    return full_vector.replace(/\(|\)/g, '').split("/");
};

const getSeverityV2 = function(Score) {
    if (Score >= 7.0) {
        return "High";
    } else if ((Score <= 6.9) && (Score >= 4.0)) {
        return "Medium";
    } else if ((Score <= 3.9) && (Score >= 0.1)) {
        return "Low";
    } else if (Score == 0) {
        return "None";
    }
};

const getSeverityV3 = function(Score) {
    if (Score >= 9.0) {
        return "Critical";
    } else if ((Score <= 8.9) && (Score >= 7.0)) {
        return "High";
    } else if ((Score <= 6.9) && (Score >= 4.0)) {
        return "Medium";
    } else if ((Score <= 3.9) && (Score >= 0.1)) {
        return "Low";
    } else if (Score == 0) {
        return "None";
    }
};

const getVectorV2 = {
    cvss: function(vector) {
        const subscore = vector.split(":");

        switch (subscore[0]) {
            case 'AV':
                switch (subscore[1]) {
                    case 'L':
                        return Array("LOCAL", 1);
                        break;
                    case 'A':
                        return Array("ADJACENT_NETWORK", 2);
                        break;
                    case 'N':
                        return Array("NETWORK", 3);
                        break;
                }
            case 'AC':
                switch (subscore[1]) {
                    case 'H':
                        return Array("HIGH", 1);
                        break;
                    case 'M':
                        return Array("MEDIUM", 2);
                        break;
                    case 'L':
                        return Array("LOW", 3);
                        break;
                }
            case 'Au':
                switch (subscore[1]) {
                    case 'M':
                        return Array("MULTIPLE_INSTANCES", 1);
                        break;
                    case 'S':
                        return Array("SINGLE_INSTANCE", 2);
                        break;
                    case 'N':
                        return Array("NONE", 3);
                        break;
                }
            case 'C':
                switch (subscore[1]) {
                    case 'N':
                        return Array("NONE", 1);
                        break;
                    case 'P':
                        return Array("PARTIAL", 2);
                        break;
                    case 'C':
                        return Array("COMPLETE", 3);
                        break;
                }
            case 'I':
                switch (subscore[1]) {
                    case 'N':
                        return Array("NONE", 1);
                        break;
                    case 'P':
                        return Array("PARTIAL", 2);
                        break;
                    case 'C':
                        return Array("COMPLETE", 3);
                        break;
                }
            case 'A':
                switch (subscore[1]) {
                    case 'N':
                        return Array("NONE", 1);
                        break;
                    case 'P':
                        return Array("PARTIAL", 2);
                        break;
                    case 'C':
                        return Array("COMPLETE", 3);
                        break;
                }
        }
    }
};

const getVectorV3 = {
    cvss: function(vector) {
        const subscore = vector.split(":");

        switch (subscore[0]) {
            case 'AV':
                switch (subscore[1]) {
                    case 'P':
                        return Array("PHYSICAL", 1);
                        break;
                    case 'L':
                        return Array("LOCAL", 2);
                        break;
                    case 'A':
                        return Array("ADJACENT_NETWORK", 3);
                        break;
                    case 'N':
                        return Array("NETWORK", 4);
                        break;
                }
            case 'AC':
                switch (subscore[1]) {
                    case 'H':
                        return Array("HIGH", 1);
                        break;
                    case 'L':
                        return Array("LOW", 3);
                        break;
                }
            case 'PR':
                switch (subscore[1]) {
                    case 'H':
                        return Array("HIGH", 1);
                        break;
                    case 'L':
                        return Array("LOW", 2);
                        break;
                    case 'N':
                        return Array("NONE", 3);
                        break;
                }
            case 'UI':
                switch (subscore[1]) {
                    case 'R':
                        return Array("REQUIRED", 1);
                        break;
                    case 'N':
                        return Array("NONE", 3);
                        break;
                }
            case 'S':
                switch (subscore[1]) {
                    case 'U':
                        return Array("UNCHANGED", 1);
                        break;
                    case 'C':
                        return Array("CHANGED", 3);
                        break;
                }
            case 'C':
                switch (subscore[1]) {
                    case 'N':
                        return Array("NONE", 1);
                        break;
                    case 'L':
                        return Array("LOW", 2);
                        break;
                    case 'H':
                        return Array("HIGH", 3);
                        break;
                }
            case 'I':
                switch (subscore[1]) {
                    case 'N':
                        return Array("NONE", 1);
                        break;
                    case 'L':
                        return Array("LOW", 2);
                        break;
                    case 'H':
                        return Array("HIGH", 3);
                        break;
                }
            case 'A':
                switch (subscore[1]) {
                    case 'N':
                        return Array("NONE", 1);
                        break;
                    case 'L':
                        return Array("LOW", 2);
                        break;
                    case 'H':
                        return Array("HIGH", 3);
                        break;
                }
        }
    }
};
// -------------------------------------------


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

    getFileList(input).then(function(fileList) {
        console.log("[INFO] : Convert start.");

        let num = 0;
        let tmp_array = [];
        fileList.forEach(function(path, i) {
            let targetObj = JSON.parse(fs.readFileSync(path, 'utf8'));
            let data = getFlatObj(targetObj);
            if (type === "csv") {
                outputData(createCsvData(data, i));
            } else
            if (type === "els") {
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