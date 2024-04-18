<besonderhede>

<opsomming><sterk>Leer AWS-hacking vanaf nul tot held met</sterk> <a href="https://training.hacktricks.xyz/courses/arte"><sterk>htARTE (HackTricks AWS Red Team Expert)</sterk></a><sterk>!</sterk></opsomming>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</besonderhede>

## WhiteIntel

<figuur><img src=".gitbook/assets/image (1224).png" alt=""><onderskrif></onderskrif></figuur>

[**WhiteIntel**](https://whiteintel.io) is 'n **donkerweb**-aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **steelmalware** is **gekompromiteer**.

Die primêre doel van WhiteIntel is om rekeningoorneem te bekamp en lospryse-aanvalle as gevolg van inligtingsteelmalware te voorkom.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% insluit url="https://whiteintel.io" %}

---

As jy 'n pcap het met data wat deur **DNSCat uitgefilter** word (sonder om versleuteling te gebruik), kan jy die uitgefilterde inhoud vind.

Jy hoef net te weet dat die **eerste 9 byte** nie werklike data is nie, maar verband hou met die **C\&C-kommunikasie**:
```python
from scapy.all import rdpcap, DNSQR, DNSRR
import struct

f = ""
last = ""
for p in rdpcap('ch21.pcap'):
if p.haslayer(DNSQR) and not p.haslayer(DNSRR):

qry = p[DNSQR].qname.replace(".jz-n-bs.local.","").strip().split(".")
qry = ''.join(_.decode('hex') for _ in qry)[9:]
if last != qry:
print(qry)
f += qry
last = qry

#print(f)
```
Vir meer inligting: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)


Daar is 'n skripsie wat werk met Python3: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```bash
python3 dnscat_decoder.py sample.pcap bad_domain
```
<besonderhede>

<opsomming><sterk>Leer AWS-hacking vanaf nul tot held met</sterk> <a href="https://training.hacktricks.xyz/courses/arte"><sterk>htARTE (HackTricks AWS Red Team Expert)</sterk></a><sterk>!</sterk></opsomming>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</besonderhede>
