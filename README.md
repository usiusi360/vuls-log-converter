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
$ git clone https://github.com/usiusi360/vuls-log-converter.git
$ cd ./vuls-log-converter
$ npm install
```


## Usage

```
Usage: vuls-log-converter.js [options]

	--help, -h
		Displays help information about this script
		'vuls-log-converter.js -h' or 'vuls-log-converter.js --help'

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

## Example

- Vuls JSON ⇒　CSV
```
# node ./vuls-log-converter.js -t csv -i /opt/vuls/results/current/ -o ./output.csv
```

- Vuls JSON ⇒　ElasticSearch
```
# node ./vuls-log-converter.js -t els -i /opt/vuls/results/current/ -e http://192.168.0.1:9200/
```

> + Setting up kibana

> index name or pattern：vuls_index

> Time-field name：ScannedAT
