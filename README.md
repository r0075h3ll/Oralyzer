<img src="https://i.ibb.co/pR55wPZ/g882.png">

### Introduction


Oralyzer, a simple python script, capable of identifying the open redirection vulnerability in a website. It does that by fuzzing the url i.e. provided as the input.

### Features

Oralyzer can identify different types of Open Redirect Vulnerabilities:
 - Header Based
 - Javascript Based
 - Meta Tag Based<br>

Oralyzer uses <a href="https://github.com/tomnomnom/waybackurls">waybackurls</a> to fetch URLs from archive.org, it then separates the URLs that have specific parameters in them, parameters that are more likely to be vulnerable.

### Installation

Use **python v3.7**<br>

```
$ git clone https://github.com/0xNanda/Oralyzer.git
$ pip3 install -r requirements.txt
$ go get github.com/tomnomnom/waybackurls
```

### Usage
<img src="https://i.ibb.co/ZH0DNhT/carbon-5.png">

### Upcoming Features

- [ ] Improved DOM XSS detection mechanism
- [ ] Test multiple parameters in one run
- [ ] Improved speed
- [x] CRLF Injection Detection 

### Contribution

You can contribute to this program in following ways:

- Create pull requests
- Report bugs
- Hit me up on <a href='http://twitter.com/0xNanda'>Twitter</a> with a new idea/feature