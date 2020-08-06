<img src="https://i.ibb.co/DLzGqVx/bitmap.png" align="center">

### Introduction


Oralyzer, a simple python script, capable of identifying the open redirection vulnerability in a website. It does that by fuzzing the url i.e. provided as the input.

### Features

Oralyzer can identify different types of Open Redirect Vulnerabilities:
 - Header Based
 - Javascript Based
 - Meta Tag Based<br>

Oralyzer uses <a href="https://github.com/tomnomnom/waybackurls">waybackurls</a> to fetch URLs from archive.org, it then separates the URLs that have specific parameters in them, parameters that are more likely to be vulnerable.

### Installation

Use <img src="https://img.shields.io/badge/python-v3.7-blue" /><br>

```
$ git clone https://github.com/0xNanda/Oralyzer.git
$ pip3 install -r requirements.txt
$ go get github.com/tomnomnom/waybackurls
```

### Usage

<img src="https://i.ibb.co/dK8Q100/carbon-7.png">

### Contribution

This program is buggy and the only way it can be improved is by your contribution. And you can do that in following ways:

- Create pull requests
- Report bugs
- Hit me up on <a href='http://twitter.com/0xNanda'>Twitter</a> with a new idea/feature
