### Introduction


Oralyzer, a simple python script that is capable of finding the open redirection vulnerability in a website. It does that by fuzzing the url i.e. provided as the input.

### Features

Oralyzer can identify following types of Open Redirect Vulnerabilities:
 - Header Based
 - Javascript Based
 - Meta Tag Based<br>

Also, Oralyzer uses its own wayback machine module to fetch URLs from web.archive.org, it then separates the URLs that have specific parameters in them, parameters that are more likely to be vulnerable.

### Installation

Use **python v3.7**<br>

```
$ git clone https://github.com/r0075h3ll/Oralyzer.git
$ pip3 install -r requirements.txt
$ go get github.com/tomnomnom/waybackurls
```

### Usage
<img src="https://i.ibb.co/4N9pKTD/carbon-just.png">

### Upcoming Features

- [ ] Improved DOM XSS detection mechanism
- [x] Test multiple parameters in one run
- [ ] Improved speed
- [x] CRLF Injection Detection

### Contribution

You can contribute to this program in following ways:

- Create pull requests
- Report bugs
- Hit me up on <a href='http://twitter.com/r0075h3ll'>Twitter</a> with a new idea/feature