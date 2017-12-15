# vuls-log-converter


[![license](https://img.shields.io/github/license/usiusi360/zabirepo.svg?style=flat-square)](https://github.com/usiusi360/vuls-log-converter/blob/master/LICENSE.txt)

## Features
- Convert Vuls's JSON file to CSV.
- Convert Vuls's JSON file and bulk insert it into ElasticSearch.


## Requirements
node.js >= latest(LTS)

npm     >= latest(LTS)

## Installation
```
# npm i -g vuls-log-converter
```

## Usage
```
Usage: vulslogconv [options]

	--help, -h
		Displays help information about this script
		'vulslogconv -h' or 'vulslogconv --help'

	--type, -t
		Output as CSV or JSON for ElasticSearch
		[csv|els]

	--input, -i
		vuls result dir
		--input=/opt/vuls/results/current/ or -i /opt/vuls/results/current/

	--output, -o
		output file name
		--output=./output.csv or -o ./output.csv

	--esEndPoint, -e
		ElasticSearch EndPoint
		--esEndPoint=http://192.168.0.1:9200/ or -e http://192.168.0.1:9200/

```

## Report in JSON format with Vuls

You need to run report processing in Vuls before conversion

```
$ vuls report --format-json
```

## Example

##### Vuls JSON ⇒　CSV
```
$ vulslogconv -t csv -i /opt/vuls/results/current/ -o ./output.csv
```

##### Vuls JSON ⇒　ElasticSearch
```
$ vulslogconv -t els -i /opt/vuls/results/current/ -e http://192.168.0.1:9200/
```

> + Setting up kibana

> index name or pattern：vuls_index

> Time-field name：ScannedAT


## OutPut Columns

By default, all items are output.

```
    "ScannedAt"
    "Platform"
    "Container"
    "ServerName"
    "Family"
    "Release"
    "CveID"
    "DetectionMethod"
    "Packages"
    "PackageVer"
    "NewPackageVer"
    "NotFixedYet"
    "CweID"
    "CVSS Score"
    "CVSS Severity"
    "CVSS (AV)"
    "CVSS (AC)"
    "CVSS (Au)"
    "CVSS (C)"
    "CVSS (I)"
    "CVSS (A)"
    "Summary"
    "Changelog"
    "PublishedDate"
    "LastModifiedDate"
```
