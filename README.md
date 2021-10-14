### Introduction


Oralyzer, a simple python script that probes for Open Redirection vulnerability in a website. It does that by fuzzing the URL that is provided in the input.

### Features

Oralyzer can identify following types of Open Redirect Vulnerabilities:
 - Header Based
 - Javascript Based
 - Meta Tag Based<br>

Also, Oralyzer has its own module to fetch URLs from web.archive.org, it then separates the URLs that have specific parameters in them, parameters that are more likely to be vulnerable.

### Installation

```
$ git clone https://github.com/r0075h3ll/Oralyzer.git
$ pip3 install -r requirements.txt
```

### Usage
<img src="https://i.ibb.co/xSdTvBW/carbon-1.png">

### Features

- [x] Improved DOM XSS detection mechanism
- [x] Test multiple parameters in one run
- [x] CRLF Injection Detection

### Contribution

You can contribute to this project in following ways:

- Create pull requests
- Report bugs
- Hit me up on <a href='http://twitter.com/r0075h3ll'>Twitter</a> with a new idea/feature