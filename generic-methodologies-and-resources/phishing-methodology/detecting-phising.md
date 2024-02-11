# Op die spoor van Phishing

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Inleiding

Om 'n phising-poging op te spoor, is dit belangrik om **die phising-tegnieke wat tans gebruik word, te verstaan**. Op die ouerbladsy van hierdie pos kan jy hierdie inligting vind, so as jy nie bewus is van watter tegnieke vandag gebruik word nie, sal ek aanbeveel dat jy na die ouerbladsy gaan en ten minste daardie afdeling lees.

Hierdie pos is gebaseer op die idee dat die **aanvallers op een of ander manier die domeinnaam van die slagoffer sal probeer naboots of gebruik**. As jou domein `example.com` genoem word en jy ge-phish word deur 'n heeltemal ander domeinnaam vir 'n rede soos `youwonthelottery.com`, sal hierdie tegnieke dit nie ontbloot nie.

## Variasies van domeinname

Dit is redelik **maklik** om daardie **phising-pogings** wat 'n **soortgelyke domeinnaam** binne die e-pos gebruik, **te ontbloot**.\
Dit is genoeg om 'n lys van die mees waarskynlike phisingname te **genereer** wat 'n aanvaller kan gebruik en te **kyk** of dit **geregistreer** is of net te kyk of daar enige **IP** is wat dit gebruik.

### Verdagte domeine vind

Vir hierdie doel kan jy enige van die volgende hulpmiddels gebruik. Let daarop dat hierdie hulpmiddels outomaties DNS-versoeke sal doen om te kyk of die domein 'n IP daaraan toegewys het:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Jy kan 'n kort verduideliking van hierdie tegniek op die ouerbladsy vind. Of lees die oorspronklike navorsing by [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**

Byvoorbeeld, 'n 1-bit-wysiging in die domein microsoft.com kan dit omskep in _windnws.com._\
**Aanvallers kan soveel moontlike bitflipping-domeine registreer wat verband hou met die slagoffer om legitieme gebruikers na hul infrastruktuur om te lei**.

**Alle moontlike bitflipping-domeinname moet ook gemonitor word.**

### Basiese kontroles

Sodra jy 'n lys potensiële verdagte domeinname het, moet jy dit **ondersoek** (veral die poorte HTTP en HTTPS) om te **sien of hulle 'n soortgelyke aanmeldingsvorm gebruik** as een van die slagoffer se domeine.\
Jy kan ook poort 3333 ondersoek om te sien of dit oop is en 'n instansie van `gophish` uitvoer.\
Dit is ook interessant om te weet **hoe oud elke ontdekte verdagte domein is**, hoe jonger dit is, hoe gevaarliker dit is.\
Jy kan ook **skermskote** van die HTTP- en/of HTTPS-verdagte webblad kry om te sien of dit verdag is en in daardie geval **toegang daartoe neem om 'n dieper kyk te neem**.

### Gevorderde kontroles

As jy 'n stap verder wil gaan, sal ek aanbeveel dat jy **hierdie verdagte domeine monitor en gereeld soek na meer** (elke dag? dit neem slegs 'n paar sekondes/minute). Jy moet ook die **oop poorte** van die betrokke IP's **ondersoek** en **soek na instansies van `gophish` of soortgelyke hulpmiddels** (ja, aanvallers maak ook foute) en **monitor die HTTP- en HTTPS-webblaaie van die verdagte domeine en subdomeine** om te sien of hulle enige aanmeldingsvorm van die slagoffer se webblaaie gekopieer het.\
Om dit te **outomatiseer**, sal ek aanbeveel om 'n lys van aanmeldingsvorms van die slagoffer se domeine te hê, die verdagte webblaaie te spider en elke aanmeldingsvorm wat binne die verdagte domeine gevind is, te vergelyk met elke aanmeldingsvorm van die slagoffer se domein deur iets soos `ssdeep` te gebruik.\
As jy die aanmeldingsvorms van die verdagte domeine gelokaliseer het, kan jy probeer om **rommelgeloofsbriewe te stuur** en **kyk of dit jou na die slagoffer se domein omskakel**.

## Domeinname met sleutelwoorde

Die ouerbladsy noem ook 'n tegniek vir die variasie van domeinname wat bestaan uit die plaas van die **slagoffer se domeinnaam binne 'n groter domein** (bv. paypal-financial.com vir paypal.com).

### Sertifikaattransparansie

Dit is nie moontlik om die vorige "Brute-Force" benadering te gebruik nie, maar dit is eintlik **moontlik om sulke phising-pogings te ontbloot** danksy sertifikaattransparansie. Telkens wanneer 'n sertifikaat deur 'n CA uitgereik word, word die besonderhede openbaar gemaak. Dit beteken dat deur die sertifikaattransparansie te lees of selfs te monitor, dit **moontlik is om domeine te vind wat 'n sleutelwoord binne hul naam gebruik**. Byvoorbeeld, as 'n aanvaller 'n sertifikaat genereer vir [https://paypal-financial.com](https://paypal-financial.com), is dit moontlik om die sleutelwoord "paypal" in die sertifikaat te vind en te weet dat 'n verdagte e-pos gebruik word.

Die pos [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) stel voor dat jy Censys kan gebruik om te soek na sertifikate wat 'n spesifieke sleutelwoord affekteer en te filter volgens datum (slegs "nuwe" sertifikate) en volgens die CA-uitreiker "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../.gitbook/assets/image (390).png>)

Jy kan egter "dieselfde" doen deur die gratis webwerf [**crt.sh**](https://crt.sh) te gebruik. Jy kan **soek na die sleutelwoord** en die resultate **filter** volgens datum en CA as jy wil.

![](<../../.gitbook/assets/image (391).png>)

Met hierdie laaste opsie kan jy selfs die veld "Matching Identities" gebruik om te sien of enige identiteit van die werklike domein ooreenstem met enige van die verdagte domeine (let daarop dat 'n verdagte domein 'n vals positief kan wees).

**'n Ander alternatief** is die fantastiese projek genaamd [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream bied 'n stroom van nuut gegenereerde sertifikate in werklike tyd wat jy kan gebruik om gespesifiseerde sleutelwoorde in (byna) werklike tyd op te spoor. In werklikheid is daar 'n projek genaamd [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) wat presies dit doen.
### **Nuwe domeine**

**Een laaste alternatief** is om 'n lys van **nuut geregistreerde domeine** vir sommige TLD's ([Whoxy](https://www.whoxy.com/newly-registered-domains/) bied so 'n diens) te versamel en **die sleutelwoorde in hierdie domeine te ondersoek**. Tog gebruik lang domeine gewoonlik een of meer subdomeine, dus sal die sleutelwoord nie binne die FLD verskyn nie en sal jy nie die phising subdomein kan vind nie.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
