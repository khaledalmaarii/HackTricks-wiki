# External Recon Methodology

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Assets discoveries

> So you were said that everything belonging to some company is inside the scope, and you want to figure out what this company actually owns.

The goal of this phase is to obtain all the **companies owned by the main company** and then all the **assets** of these companies. To do so, we are going to:

1. Find the acquisitions of the main company, this will give us the companies inside the scope.
2. Find the ASN (if any) of each company, this will give us the IP ranges owned by each company
3. Use reverse whois lookups to search for other entries (organisation names, domains...) related to the first one (this can be done recursively)
4. Use other techniques like shodan `org`and `ssl`filters to search for other assets (the `ssl` trick can be done recursively).

### **Acquisitions**

First of all, we need to know which **other companies are owned by the main company**.\
One option is to visit [https://www.crunchbase.com/](https://www.crunchbase.com), **search** for the **main company**, and **click** on "**acquisitions**". There you will see other companies acquired by the main one.\
Other option is to visit the **Wikipedia** page of the main company and search for **acquisitions**.

> Ok, at this point you should know all the companies inside the scope. Lets figure out how to find their assets.

### **ASNs**

An autonomous system number (**ASN**) is a **unique number** assigned to an **autonomous system** (AS) by the **Internet Assigned Numbers Authority (IANA)**.\
An **AS** consists of **blocks** of **IP addresses** which have a distinctly defined policy for accessing external networks and are administered by a single organisation but may be made up of several operators.

It's interesting to find if the **company have assigned any ASN** to find its **IP ranges.** It will be interested to perform a **vulnerability test** against all the **hosts** inside the **scope** and **look for domains** inside these IPs.\
You can **search** by company **name**, by **IP** or by **domain** in [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Depending on the region of the company this links could be useful to gather more data:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Anyway, probably all the** useful information **(IP ranges and Whois)** appears already in the first link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Qapla', [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'eS** subdomain enumeration automatically aggregates and summarizes ASNs at the end of the scan.
```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```
**IP ranges** of an organisation can be found using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
**IP and ASN** of a domain can be found using [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

At this point we known **all the assets inside the scope**, so if you are allowed you could launch some **vulnerability scanner** (Nessus, OpenVAS) over all the hosts.\
Also, you could launch some [**port scans**](../pentesting-network/#discovering-hosts-from-the-outside) **or use services like** shodan **to find** open ports **and depending on what you find you should** take a look in this book to how to pentest several possible services running.\
**Also, It could be worth it to mention that you can also prepare some** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> We know all the companies inside the scope and their assets, it's time to find the domains inside the scope.

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

First of all you should look for the **main domain**(s) of each company. For example, for _Tesla Inc._ is going to be _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs to find more domains inside the scope**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
### **Reverse Whois (loop)**

**QaH**DI' **whois** vItlhutlh **information** **lot** **organisation name**, **address**, **emails**, phone numbers... **'e'** **interesting** **'e'** **assets related to the company** **find** **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
**online tools** **use**:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, **free API**.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - **free**
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - **free** (only **100 free** searches)
* [https://www.domainiq.com/](https://www.domainiq.com) - **free**

**DomLink** **automate** **task** **use** [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
**automatic reverse whois discovery** **perform** **amass** (https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note** **use** **technique** **discover** **domain names** **time** **find** **domain**.

### **Trackers**

**ID** **tracker** **same ID of the same tracker** **find** **2 different pages** **suppose** **pages** **managed by the same team**.\
**example**, **see** **Google Analytics ID** **Adsense ID** **pages**.

**pages** **tools** **search** **trackers**:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

**Did** **know** **related domains and sub domains** **target** **looking for the same favicon icon hash**? **exactly** **favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool **made** [@m4ll0k2](https://twitter.com/m4ll0k2) **does**. **Here’s** **use** **it**:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - Discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

**ghItlhmeH, favihash** vItlhutlhlaHbe'chugh, **jatlh favicon icon hash** vItlhutlhlaHbe'chugh, **target** vItlhutlhlaHbe'chugh, **domains** vItlhutlhlaHbe'chugh, **jatlh**.

**vItlhutlhlaHbe'chugh**, **favicon hash** vItlhutlhlaHbe'chugh, **web tech** vItlhutlhlaHbe'chugh, **vulnerable version** vItlhutlhlaHbe'chugh, **shodan** vItlhutlhlaHbe'chugh, **vulnerable places** vItlhutlhlaHbe'chugh, **search** vItlhutlhlaHbe'chugh.
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
**ghItlhvam** **favicon hash** **cha'logh** **web** **neH**:

1. **Download** the **favicon** **image** from the **web** **page**. You can **use** the **browser's developer tools** or **download** it **manually**.

2. **Calculate** the **MD5 hash** of the **favicon** **image**. You can **use** **online tools** or **command-line utilities** like **md5sum**.

3. **Convert** the **MD5 hash** to **base64** encoding. This can be done **using** **online tools** or **command-line utilities** like **base64**.

4. **Remove** any **padding** characters (=) from the **base64** **encoded** **hash**.

5. **Convert** the **base64** **encoded** **hash** to **hexadecimal** representation. This can be done **using** **online tools** or **command-line utilities** like **xxd**.

6. **The resulting hexadecimal hash** is the **favicon hash** of the **web** **page**.

**ghItlhvam** **favicon hash** **cha'logh** **web** **neH**:

1. **Download** the **favicon** **image** **web** **page**. **browser's developer tools** **use** **can** **manually** **download** **or**.

2. **Calculate** the **MD5 hash** **favicon** **image**. **online tools** **use** **can** **md5sum** **utilities** **command-line** **like**.

3. **Convert** the **MD5 hash** **base64** **encoding**. **online tools** **use** **can** **base64** **utilities** **command-line** **like**.

4. **Remove** **padding** **characters** (=) **base64** **encoded** **hash**.

5. **Convert** **base64** **encoded** **hash** **hexadecimal** **representation**. **online tools** **use** **can** **xxd** **utilities** **command-line** **like**.

6. **The resulting hexadecimal hash** **favicon hash** **web** **page**.
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
### **Copyright / Uniq string**

Search inside the web pages **strings that could be shared across different webs in the same organisation**. The **copyright string** could be a good example. Then search for that string in **google**, in other **browsers** or even in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

It's common to have a cron job such as
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### **Qa'vIn Takeover**

Qa'vInmeyDaq subdomainmey IPmeyDaq yIqawlaHbe'chugh, 'ach DNS qetbogh vItlhutlh. So'wI'pu' Digital Ocean jImej 'ej VM vItlhutlh, qaStaHvIS subdomain(mey) yIqawlaHbe'chugh.

[**chu' vItlhutlh**](https://kmsec.uk/blog/passive-takeover/) vItlhutlh 'e' vItlhutlh DigitalOcean jImej VM vItlhutlh, 'ej 'oH vItlhutlh 'e' vItlhutlh IPv4 vItlhutlh, 'ej 'oH vItlhutlh 'e' vItlhutlh Virustotal vItlhutlh subdomain vItlhutlh.

### **lo'laHbe'**

**Qa'vInmeyDaq vItlhutlh** vItlhutlh 'e' vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

**OSINT** (Open Source Intelligence) jup 'oH **tools** 'e' vItlhutlh. **tools** **DIvI'** (API keys configure results better for):

* [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
* [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
* [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
* [**findomain**](https://github.com/Edu4rdSHL/findomain/)
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/tlh)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
**ghItlhvam** **tlhIngan** **tools/APIs** **'oH** **vItlhutlh** **ghaH** **ghaH** **subdomains** **Dajatlh** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC vaj API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) **mIw rapIDnS** free API
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
* [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
* [**gau**](https://github.com/lc/gau)**:** AlienVault's Open Threat Exchange, Wayback Machine, je Common Crawl jImej jImejta' domain'e' vItlhutlh.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): **tlhIngan Hol** vItlhutlh **&** **subscraper**: **web** vItlhutlh **JS** lo'laHbe' **'ej** subdomains **ghItlh**.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) has a free API to search for subdomains and IP history
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

This project offers for **free all the subdomains related to bug-bounty programs**. You can access this data also using [chaospy](https://github.com/dr-0x0x/chaospy) or even access the scope used by this project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

You can find a **comparison** of many of these tools here: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Let's try to find new **subdomains** brute-forcing DNS servers using possible subdomain names.

For this action you will need some **common subdomains wordlists like**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

And also IPs of good DNS resolvers. In order to generate a list of trusted DNS resolvers you can download the resolvers from [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) and use [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) to filter them. Or you could use: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

The most recommended tools for DNS brute-force are:

* [**massdns**](https://github.com/blechschmidt/massdns): This was the first tool that performed an effective DNS brute-force. It's very fast however it's prone to false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): **gobuster** vItlhutlh 1 resolver vItlhutlh.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) jImej around `massdns`, goDaqDaq vItlhutlh 'ej vItlhutlh subdomains valid using bruteforce, 'ej subdomains resolve vItlhutlh 'ej input-output support vItlhutlh.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): **puredns** jatlh **massdns** lo'laHbe'.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) uses asyncio to brute force domain names asynchronously.

* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) **async**-tIq vItlhutlh **aiodnsbrute** **asynchronously** **domain names** **brute force** **uses**.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### cha'logh DNS Brute-Force Qap

ghItlhvam open sources 'ej brute-forcing vItlhutlh subdomains, vaj subdomains found alterations generate 'ej 'oH tools 'oH vItlhutlh:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** domains 'ej subdomains generate permutations.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): **tlhIngan**. Domains je subdomains vItlhutlh.
* **wordlist** goaltdns permutations **'e'** [**'oH**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** tlhInganpu' jImejDaq je subdomains Domains je. DaH jImejDaq permutations file 'e' vItlhutlh. gotator vItlhutlh.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): **altdns** **(https://github.com/infosec-au/altdns)**: Subdomain permutations can be generated using this tool. It also has the capability to resolve them, although it is recommended to use the previously mentioned tools.
* **altdns** **wordlist** can be obtained from [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): **dmut** vItlhutlhlaHbe'chugh, subdomains permutations, mutations, je alteration pe'vIl. **dmut** vItlhutlhlaHbe'chugh, brute force vItlhutlhlaHbe'chugh (DNS wild card vItlhutlhlaHbe'chugh).
* **dmut** permutations wordlist **[**ghaH**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)** vItlhutlhlaHbe'.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** **Domain** vItlhutlh **new potential subdomains names** **generates** based on **patterns** **indicated** to try to **discover** more subdomains.

#### Smart permutations generation

* [**regulator**](https://github.com/cramppet/regulator): **Info** **more** **read** this [**post**](https://cramppet.github.io/regulator/index.html) **but** **main parts** **discovered subdomains** **get** and **mix** them **find** more subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ jup 'ej subdomain brute-force fuzzer coupled with an immensly simple but effective DNS reponse-guided algorithm. vaj vItlhutlh input data, DaH jatlh wordlist or historical DNS/TLS records, accurately synthesize more corresponding domain names 'ej expand them even further in a loop based on information gathered during DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Check this blog post I wrote about how to **automate the subdomain discovery** from a domain using **Trickest workflows** so I don't need to launch manually a bunch of tools in my computer:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Virtual Hosts**

If you found an IP address containing **one or several web pages** belonging to subdomains, you could try to **find other subdomains with webs in that IP** by looking in **OSINT sources** for domains in an IP or by **brute-forcing VHost domain names in that IP**.

#### OSINT

You can find some **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs**.

**Brute Force**

If you suspect that some subdomain can be hidden in a web server you could try to brute force it:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
{% hint style="info" %}
Qa'vIn technique vItlhutlhlaHbe'chugh, 'ej 'oH 'e' vItlhutlhlaHbe'chugh 'e' vItlhutlhlaHbe'chugh.
{% endhint %}

### **CORS Brute Force**

QaStaHvIS, 'ej pagh 'oH 'e' vItlhutlhlaHbe'chugh _**Access-Control-Allow-Origin**_ header vItlhutlhlaHbe'chugh 'ej _**Origin**_ header vItlhutlhlaHbe'chugh 'e' vItlhutlhlaHbe'chugh, 'ach pagh vItlhutlhlaHbe'chugh 'e' vItlhutlhlaHbe'chugh **subdomains** **discover** vItlhutlhlaHbe'chugh.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**Subdomains** yIbuS **ghItlh** **bucket** **ghItlh** **cha'logh** **qar'a'** [**permissions**](../../network-services-pentesting/pentesting-web/buckets/) **yIlo'.**\
**Scope** **ghItlh** **qar'a'** **subdomains** **ghItlh** **bucket** **yIlo'** **[brute force** **possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitorization**

**Certificate Transparency** Logs **sublert** [**subdomains** **ghItlh** **new subdomains** **monitor** **yIlo'.**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)

### **Looking for vulnerabilities**

[**Subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) **yIlo'.**\
**Subdomain** **S3 bucket** **ghItlh** [**permissions**](../../network-services-pentesting/pentesting-web/buckets/) **yIlo'.**

**subdomain** **IP** **ghItlh** **subdomains** **assets discovery** **ghItlh** **IP** **vulnerability scan** **yIlo'** (Nessus or OpenVAS **vulnerability scan** **yIlo'**) **[port scan**](../pentesting-network/#discovering-hosts-from-the-outside) **nmap/masscan/shodan** **yIlo'.** **services** **running** **tricks** **attack** **[this book some tricks to "attack" them** **yIlo'.**\
_Note** **subdomain** **IP** **client** **controlled** **IP** **scope** **ghItlh** **be careful**._

## IPs

**IP ranges, domains and subdomains** **ghItlh** **found** **initial steps** **yIlo'.**\
**IPs** **recollect** **those ranges** **domains/subdomains (DNS queries)** **yIlo'.**

**free apis** **previous IPs used by domains and subdomains** **yIlo'.** **IPs** **client** **owned** **[CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) **yIlo'.**

* [**https://securitytrails.com/**](https://securitytrails.com/)

**specific IP address** **domains pointing** **hakip2host** **[hakip2host** **tool** **yIlo'.](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**CDNs** **belong** **IPs** **[Port scan** **yIlo'** (as you highly probably won’t find anything interested in there). **running services** **vulnerabilities** **yIlo'.**

**[guide** **yIlo'.](../pentesting-network/) **scan hosts** **how to scan hosts.**

## Web servers hunting

> **companies** **assets** **IP ranges, domains and subdomains** **found** **search** **web servers** **yIlo'.**

**recon** **IPs and domains discovered** **performed** **previous steps** **possible web servers** **found** **may have**. **fast tricks** **search** **web servers** **inside the scope** **going** **see**.

**web apps discovery** **oriented** **method** **ports open** **web** servers **masscan** [**here**](../pentesting-network/#http-port-discovery) **yIlo'.**\
**friendly tool** **web servers** [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) **[**httpx**](https://github.com/projectdiscovery/httpx) **yIlo'.** **list** **domains** **connect** **port 80 (http) and 443 (https)** **yIlo'.** **indicate** **ports** **try**
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

                                                                                                                                  
## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/)

**QaH** **vulnerabilities** **majority** found **bug hunters** **web applications**, **web application testing methodology** **talk** **web application testing methodology**, **[**information here**](../../network-services-pentesting/pentesting-web/)** **find**.

**QaH** **special mention** **section** [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/#automatic-scanners), **expect** **find** **sensitive vulnerabilities**, **handy** **implement** **workflows** **initial web information.**

## Recapitulation

> **Qapla'**! **QaH** **perform** **basic enumeration**. **HIq** **basic** **enumeration** **(tricks later)**.

**So** **already**:

1. **QaH** **companies** **inside** **scope**
2. **QaH** **assets** **belonging** **companies** (**vuln scan** **scope**)
3. **QaH** **domains** **belonging** **companies**
4. **QaH** **subdomains** **domains** (**subdomain takeover**?)
5. **QaH** **IPs** (**CDNs**)
6. **QaH** **web servers** **screenshot** (**weird** **deeper look**?)
7. **QaH** **potential public cloud assets** **belonging** **company**.
8. **Emails**, **credentials leaks**, **secret leaks** **big win** **easily**.
9. **Pentesting** **webs** **found**

## **Full Recon Automatic Tools**

**tools** **perform** **proposed actions** **given scope**.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - **old** **updated**

## **References**

* **free courses** [**@Jhaddix**](https://twitter.com/Jhaddix) **[**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** **Intigriti**, **premium bug bounty platform created by hackers, for hackers**! **Join us** [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) **today**, **start earning bounties up to $100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

**ways** **support HackTricks**:

* **company advertised** **HackTricks** **download HackTricks** **PDF** **Check** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* **official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Discover** [**The PEASS Family**](https://opensea.io/collection/the-peass-family), **collection** **exclusive NFTs**
* **Join** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group**](https://t.me/peass) **follow** **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share** **hacking tricks** **submitting PRs** **HackTricks** **HackTricks Cloud** github repos.

</details>
