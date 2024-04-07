# Opmerking van Phishing

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Inleiding

Om 'n phising-poging op te spoor, is dit belangrik om **die phising-tegnieke wat tans gebruik word, te verstaan**. Op die ouerbladsy van hierdie pos kan jy hierdie inligting vind, so as jy nie bewus is van watter tegnieke tans gebruik word nie, beveel ek aan om na die ouerbladsy te gaan en ten minste daardie afdeling te lees.

Hierdie pos is gebaseer op die idee dat die **aanvallers op een of ander manier die slagoffer se domeinnaam sal probeer naboots of gebruik**. As jou domein `voorbeeld.com` genoem word en jy gevis word met 'n heeltemal ander domeinnaam om een of ander rede soos `jyhetdiegelukkigewen.com`, gaan hierdie tegnieke dit nie ontbloot nie.

## Domeinnaamvariasies

Dit is redelik **maklik** om daardie **phising-pogings** op te **spoor** wat 'n **soortgelyke domeinnaam** binne die e-pos sal gebruik.\
Dit is genoeg om 'n lys van die mees waarskynlike phisingname wat 'n aanvaller kan gebruik, te **genereer** en **te kontroleer** of dit **geregistreer** is of net te kyk of daar enige **IP** is wat dit gebruik.

### Vind verdagte domeine

Vir hierdie doel kan jy enige van die volgende gereedskap gebruik. Let daarop dat hierdie gereedskap ook outomaties DNS-versoeke sal uitvoer om te kontroleer of die domein enige IP daaraan toegewys het:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Jy kan 'n kort verduideliking van hierdie tegniek op die ouerbladsy vind. Of lees die oorspronklike navorsing in** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Byvoorbeeld, 'n 1-bit-wysiging in die domein microsoft.com kan dit omskep in _windnws.com._\
**Aanvallers kan soveel bit-flipping-domeine registreer as moontlik wat verband hou met die slagoffer om legitieme gebruikers na hul infrastruktuur te stuur**.

**Alle moontlike bit-flipping-domeinname moet ook gemonitor word.**

### Basiese kontroles

Sodra jy 'n lys van potensiële verdagte domeinname het, moet jy hulle **kontroleer** (veral die poorte HTTP en HTTPS) om te **sien of hulle 'n aanmeldingsvorm gebruik wat soortgelyk is** aan een van die slagoffer se domein.\
Jy kan ook poort 3333 kontroleer om te sien of dit oop is en 'n instansie van `gophish` uitvoer.\
Dit is ook interessant om te weet **hoe oud elke ontdekte verdagte domein is**, hoe jonger dit is, hoe riskanter dit is.\
Jy kan ook **skermskote** van die HTTP en/of HTTPS verdagte webblad kry om te sien of dit verdag lyk en in daardie geval dit **toegang om 'n dieper kyk te neem**.

### Gevorderde kontroles

As jy 'n stap verder wil gaan, sal ek aanbeveel om **daardie verdagte domeine te monitor en soek na meer** van tyd tot tyd (elke dag? dit neem net 'n paar sekondes/minute). Jy moet ook **die oop poorte** van die verwante IP's **kontroleer** en **soek na instansies van `gophish` of soortgelyke gereedskap** (ja, aanvallers maak ook foute) en **monitor die HTTP- en HTTPS-webblaaie van die verdagte domeine en subdomeine** om te sien of hulle enige aanmeldingsvorm van die slagoffer se webblaaie gekopieer het.\
Om dit te **outomatiseer** sal ek aanbeveel om 'n lys van aanmeldingsvorms van die slagoffer se domeine te hê, die verdagte webblaaie te spin en elke aanmeldingsvorm wat binne die verdagte domeine gevind is, te vergelyk met elke aanmeldingsvorm van die slagoffer se domein deur iets soos `ssdeep` te gebruik.\
As jy die aanmeldingsvorms van die verdagte domeine gelokaliseer het, kan jy probeer om **rommelgelde** te stuur en **te kontroleer of dit jou na die slagoffer se domein omskakel**.

## Domeinnamen wat sleutelwoorde gebruik

Die ouerbladsy noem ook 'n domeinnaamvariasietegniek wat bestaan uit die plaas van die **slagoffer se domeinnaam binne 'n groter domein** (bv. paypal-financial.com vir paypal.com).

### Sertifikaatdeursigtigheid

Dit is nie moontlik om die vorige "Brute-Force" benadering te volg nie, maar dit is eintlik **moontlik om sulke phising-pogings te ontbloot** ook danksy sertifikaatdeursigtigheid. Elke keer as 'n sertifikaat deur 'n CA uitgereik word, word die besonderhede openbaar gemaak. Dit beteken dat deur die sertifikaatdeursigtigheid te lees of selfs te monitor, dit **moontlik is om domeine te vind wat 'n sleutelwoord binne hul naam gebruik** Byvoorbeeld, as 'n aanvaller 'n sertifikaat van [https://paypal-financial.com](https://paypal-financial.com) genereer, is dit moontlik om die sleutelwoord "paypal" te vind en te weet dat 'n verdagte e-pos gebruik word.

Die pos [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) stel voor dat jy Censys kan gebruik om te soek na sertifikate wat 'n spesifieke sleutelwoord affekteer en te filter op datum (slegs "nuwe" sertifikate) en op die CA-uitreiker "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1112).png>)

Nietemin kan jy dieselfde doen deur die gratis web [**crt.sh**](https://crt.sh) te gebruik. Jy kan **soek na die sleutelwoord** en die resultate **filtreer** op **datum en CA** indien jy wil.

![](<../../.gitbook/assets/image (516).png>)

Deur hierdie laaste opsie te gebruik, kan jy selfs die veld Matching Identities gebruik om te sien of enige identiteit van die werklike domein ooreenstem met enige van die verdagte domeine (let daarop dat 'n verdagte domein 'n vals positief kan wees).

**'n Ander alternatief** is die fantastiese projek genaamd [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream bied 'n stroom van nuut gegenereerde sertifikate in werklike tyd wat jy kan gebruik om gespesifiseerde sleutelwoorde in (byna) werklike tyd op te spoor. In werklikheid is daar 'n projek genaamd [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) wat presies dit doen.
### **Nuwe domeine**

**Een laaste alternatief** is om 'n lys van **nuutgeregistreerde domeine** vir sommige TLD's te versamel ([Whoxy](https://www.whoxy.com/newly-registered-domains/) bied so 'n diens aan) en **die sleutelwoorde in hierdie domeine te kontroleer**. Tog gebruik lang domeine gewoonlik een of meer subdomeine, daarom sal die sleutelwoord nie binne die FLD verskyn nie en sal jy nie in staat wees om die hengel subdomein te vind.
