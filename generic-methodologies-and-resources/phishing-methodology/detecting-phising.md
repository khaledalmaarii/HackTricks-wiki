# Detecting Phishing

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Introduction

Om 'n phishing poging te ontdek, is dit belangrik om die **phishing tegnieke wat vandag gebruik word te verstaan**. Op die ouer bladsy van hierdie pos, kan jy hierdie inligting vind, so as jy nie bewus is van watter tegnieke vandag gebruik word nie, beveel ek aan dat jy na die ouer bladsy gaan en ten minste daardie afdeling lees.

Hierdie pos is gebaseer op die idee dat die **aanvallers op een of ander manier die slagoffer se domeinnaam sal probeer naboots of gebruik**. As jou domein `example.com` genoem word en jy gephish word met 'n heeltemal ander domeinnaam om een of ander rede soos `youwonthelottery.com`, sal hierdie tegnieke dit nie ontdek nie.

## Domain name variations

Dit is **redelik maklik** om die **phishing** pogings wat 'n **soortgelyke domein** naam in die e-pos gebruik, te **ontdek**.\
Dit is genoeg om 'n **lys van die mees waarskynlike phishing name** wat 'n aanvaller mag gebruik te **genereer** en te **kontroleer** of dit ** geregistreer** is of net te kyk of daar enige **IP** is wat dit gebruik.

### Finding suspicious domains

Vir hierdie doel kan jy enige van die volgende gereedskap gebruik. Let daarop dat hierdie gereedskap ook DNS versoeke outomaties sal uitvoer om te kyk of die domein enige IP aan toegeken het:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Jy kan 'n kort verduideliking van hierdie tegniek op die ouer bladsy vind. Of lees die oorspronklike navorsing in** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Byvoorbeeld, 'n 1 bit verandering in die domein microsoft.com kan dit in _windnws.com_ transformeer.\
**Aanvallers mag soveel bit-flipping domeine registreer as moontlik wat verband hou met die slagoffer om wettige gebruikers na hul infrastruktuur te herlei**.

**Alle moontlike bit-flipping domeinnames moet ook gemonitor word.**

### Basic checks

Sodra jy 'n lys van potensieel verdagte domeinnames het, moet jy hulle **kontroleer** (hoofsaaklik die poorte HTTP en HTTPS) om te **sien of hulle 'n aanmeldvorm gebruik wat soortgelyk is** aan iemand van die slagoffer se domein.\
Jy kan ook poort 3333 kontroleer om te sien of dit oop is en 'n instance van `gophish` draai.\
Dit is ook interessant om te weet **hoe oud elke ontdekte verdagte domein is**, hoe jonger dit is, hoe riskanter is dit.\
Jy kan ook **skermskote** van die HTTP en/of HTTPS verdagte webblad kry om te sien of dit verdag is en in daardie geval **dit betree om 'n dieper kyk te neem**.

### Advanced checks

As jy een stap verder wil gaan, beveel ek aan dat jy **daardie verdagte domeine monitor en van tyd tot tyd meer soek** (elke dag? dit neem net 'n paar sekondes/minute). Jy moet ook die oop **poorte** van die verwante IPs **kontroleer** en **soek na instances van `gophish` of soortgelyke gereedskap** (ja, aanvallers maak ook foute) en **monitor die HTTP en HTTPS webbladsye van die verdagte domeine en subdomeine** om te sien of hulle enige aanmeldvorm van die slagoffer se webbladsye gekopieer het.\
Om dit te **automateer**, beveel ek aan om 'n lys van aanmeldvorms van die slagoffer se domeine te hê, die verdagte webbladsye te spinn en elke aanmeldvorm wat in die verdagte domeine gevind word met elke aanmeldvorm van die slagoffer se domein te vergelyk met iets soos `ssdeep`.\
As jy die aanmeldvorms van die verdagte domeine geleë het, kan jy probeer om **rommel geloofsbriewe te stuur** en **te kyk of dit jou na die slagoffer se domein herlei**.

## Domain names using keywords

Die ouer bladsy noem ook 'n domeinnaam variasie tegniek wat bestaan uit die **slagoffer se domeinnaam binne 'n groter domein te plaas** (bv. paypal-financial.com vir paypal.com).

### Certificate Transparency

Dit is nie moontlik om die vorige "Brute-Force" benadering te neem nie, maar dit is eintlik **moontlik om sulke phishing pogings te ontdek** ook danksy sertifikaat deursigtigheid. Elke keer as 'n sertifikaat deur 'n CA uitgereik word, word die besonderhede publiek gemaak. Dit beteken dat deur die sertifikaat deursigtigheid te lees of selfs dit te monitor, dit **moontlik is om domeine te vind wat 'n sleutelwoord in sy naam gebruik**. Byvoorbeeld, as 'n aanvaller 'n sertifikaat van [https://paypal-financial.com](https://paypal-financial.com) genereer, kan jy deur die sertifikaat te kyk die sleutelwoord "paypal" vind en weet dat 'n verdagte e-pos gebruik word.

Die pos [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) stel voor dat jy Censys kan gebruik om sertifikate wat 'n spesifieke sleutelwoord beïnvloed te soek en te filter op datum (slegs "nuwe" sertifikate) en deur die CA-uitreiker "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

Jy kan egter "die dieselfde" doen met die gratis web [**crt.sh**](https://crt.sh). Jy kan **soek na die sleutelwoord** en die **resultate filter** **op datum en CA** as jy wil.

![](<../../.gitbook/assets/image (519).png>)

Met hierdie laaste opsie kan jy selfs die veld ooreenstemmende identiteite gebruik om te sien of enige identiteit van die werklike domein ooreenstem met enige van die verdagte domeine (let daarop dat 'n verdagte domein 'n vals positiewe kan wees).

**Nog 'n alternatief** is die fantastiese projek genaamd [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream bied 'n regte-tyd stroom van nuut gegenereerde sertifikate wat jy kan gebruik om gespesifiseerde sleutelwoorde in (naby) regte tyd te ontdek. Trouens, daar is 'n projek genaamd [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) wat presies dit doen.

### **New domains**

**Een laaste alternatief** is om 'n lys van **nuut geregistreerde domeine** vir sommige TLDs te versamel ([Whoxy](https://www.whoxy.com/newly-registered-domains/) bied so 'n diens) en **die sleutelwoorde in hierdie domeine te kontroleer**. Maar, lang domeine gebruik gewoonlik een of meer subdomeine, daarom sal die sleutelwoord nie binne die FLD verskyn nie en jy sal nie in staat wees om die phishing subdomein te vind nie.

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
