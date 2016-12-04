# vuls-log-converter


[![license](https://img.shields.io/github/license/usiusi360/zabirepo.svg?style=flat-square)](https://github.com/usiusi360/vuls-log-converter/blob/master/LICENSE.txt)

## Features
- Converts the JSON file output by Vuls to CSV.
- Converts the JSON file output by Vuls to bulk data of ElasticSearch. 


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
		--esEndPoint=https://hogehoge.com/ or -e https://hogehoge.com/

```

