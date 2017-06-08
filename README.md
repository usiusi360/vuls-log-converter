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
$ npm i -g vuls-log-converter
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

        --config, -c
                config file [option]
                --config=./config.json or -c ./config.json
```

## Example

- Vuls JSON ⇒　CSV
```
# vulslogconv -t csv -i /opt/vuls/results/current/ -o ./output.csv
```

- Vuls JSON ⇒　ElasticSearch
```
# vulslogconv -t els -i /opt/vuls/results/current/ -e http://192.168.0.1:9200/
```

> + Setting up kibana

> index name or pattern：vuls_index

> Time-field name：ScannedAT


## Option

By default, all items are output.

To restrict the items to be output, create "config.json" and specify it in the - config option.

```
# cat config.json 

[
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
]

```
