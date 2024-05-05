# macOS Sistemski ekstenzije

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Sistemski ekstenzije / Okvir za bezbednost krajnjih tačaka

Za razliku od Kernel ekstenzija, **Sistemski ekstenzije se izvršavaju u korisničkom prostoru** umesto u jezgru, smanjujući rizik od pada sistema zbog neispravnosti ekstenzije.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Postoje tri vrste sistemskih ekstenzija: **DriverKit** ekstenzije, **Mrežne** ekstenzije i **Ekstenzije za bezbednost krajnjih tačaka**.

### **DriverKit Ekstenzije**

DriverKit je zamena za kernel ekstenzije koje **pružaju podršku za hardver**. Omogućava drajverima uređaja (kao što su USB, serijski, NIC i HID drajveri) da se izvršavaju u korisničkom prostoru umesto u jezgru. DriverKit okvir uključuje **verzije određenih I/O Kit klasa u korisničkom prostoru**, a jezgro prosleđuje normalne događaje I/O Kit-a u korisnički prostor, nudeći sigurnije okruženje za izvršavanje ovih drajvera.

### **Mrežne Ekstenzije**

Mrežne ekstenzije omogućavaju prilagođavanje mrežnih ponašanja. Postoje nekoliko vrsta Mrežnih Ekstenzija:

* **App Proxy**: Koristi se za kreiranje VPN klijenta koji implementira protokol VPN-a orijentisan na tokove. To znači da upravlja mrežnim saobraćajem na osnovu veza (ili tokova) umesto pojedinačnih paketa.
* **Packet Tunnel**: Koristi se za kreiranje VPN klijenta koji implementira protokol VPN-a orijentisan na pakete. To znači da upravlja mrežnim saobraćajem na osnovu pojedinačnih paketa.
* **Filter Data**: Koristi se za filtriranje mrežnih "tokova". Može pratiti ili menjati mrežne podatke na nivou toka.
* **Filter Packet**: Koristi se za filtriranje pojedinačnih mrežnih paketa. Može pratiti ili menjati mrežne podatke na nivou paketa.
* **DNS Proxy**: Koristi se za kreiranje pružaoca DNS-a. Može se koristiti za praćenje ili menjanje DNS zahteva i odgovora.

## Okvir za bezbednost krajnjih tačaka

Endpoint Security je okvir koji pruža Apple u macOS-u koji pruža skup API-ja za sistemsku bezbednost. Namijenjen je za korišćenje od strane **sigurnosnih prodavaca i programera za izgradnju proizvoda koji mogu pratiti i kontrolisati aktivnosti sistema** kako bi identifikovali i zaštitili se od zlonamernih aktivnosti.

Ovaj okvir pruža **kolekciju API-ja za praćenje i kontrolu aktivnosti sistema**, kao što su izvršavanje procesa, događaji sistema datoteka, mrežni i jezgrovni događaji.

Srce ovog okvira je implementirano u jezgru, kao Kernel Ekstenzija (KEXT) smeštena na **`/System/Library/Extensions/EndpointSecurity.kext`**. Ova KEXT se sastoji od nekoliko ključnih komponenti:

* **EndpointSecurityDriver**: Deluje kao "ulazna tačka" za kernel ekstenziju. To je glavna tačka interakcije između OS-a i Endpoint Security okvira.
* **EndpointSecurityEventManager**: Ova komponenta je odgovorna za implementaciju kernel kuka. Kernel kuke omogućavaju okviru da prati sistemski događaje presretanjem sistemskih poziva.
* **EndpointSecurityClientManager**: Upravlja komunikacijom sa korisničkim prostorom klijenata, prateći koji klijenti su povezani i trebaju primati obaveštenja o događajima.
* **EndpointSecurityMessageManager**: Šalje poruke i obaveštenja o događajima korisničkom prostoru klijenata.

Dogadjaji koje Endpoint Security okvir može pratiti su kategorizovani u:

* Događaji datoteka
* Događaji procesa
* Događaji soketa
* Jezgrovni događaji (kao što su učitavanje/isključivanje kernel ekstenzije ili otvaranje I/O Kit uređaja)

### Arhitektura Okvira za bezbednost krajnjih tačaka

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Komunikacija sa korisničkim prostorom** sa Okvirom za bezbednost krajnjih tačaka dešava se putem klase IOUserClient. Koriste se dve različite podklase, u zavisnosti od vrste pozivaoca:

* **EndpointSecurityDriverClient**: Zahteva `com.apple.private.endpoint-security.manager` ovlašćenje, koje poseduje samo sistemski proces `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Zahteva `com.apple.developer.endpoint-security.client` ovlašćenje. Ovo bi obično koristio sigurnosni softver treće strane koji treba da interaguje sa Okvirom za bezbednost krajnjih tačaka.

Ekstenzije za bezbednost krajnjih tačaka:**`libEndpointSecurity.dylib`** je C biblioteka koju sistemski ekstenzije koriste za komunikaciju sa jezgrom. Ova biblioteka koristi I/O Kit (`IOKit`) za komunikaciju sa Endpoint Security KEXT-om.

**`endpointsecurityd`** je ključni sistemski demon koji je uključen u upravljanje i pokretanje sistemskih ekstenzija za bezbednost krajnjih tačaka, posebno tokom rane faze pokretanja. **Samo sistemski ekstenzije** označene sa **`NSEndpointSecurityEarlyBoot`** u njihovom `Info.plist` fajlu dobijaju ovaj tretman rane faze pokretanja.

Još jedan sistemski demon, **`sysextd`**, **validira sistemskie ekstenzije** i premješta ih na odgovarajuće lokacije u sistemu. Zatim traži odgovarajućem demonu da učita ekstenziju. **`SystemExtensions.framework`** je odgovoran za aktiviranje i deaktiviranje sistemskih ekstenzija.

## Zaobilazak ESF

ESF se koristi od strane sigurnosnih alata koji će pokušati da otkriju red timera, pa bilo kakva informacija o tome kako se to može izbeći zvuči interesantno.

### CVE-2021-30965

Stvar je u tome da sigurnosna aplikacija mora imati **Dozvole za pun pristup disku**. Dakle, ako napadač može ukloniti to, može sprečiti softver da se pokrene:
```bash
tccutil reset All
```
Za **više informacija** o ovom zaobilazenju i srodnim proverite predavanje [#OBTS v5.0: "Achillesova peta EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Na kraju je ovo rešeno davanjem nove dozvole **`kTCCServiceEndpointSecurityClient`** aplikaciji za bezbednost koju upravlja **`tccd`** tako da `tccutil` neće očistiti njene dozvole sprečavajući je da se pokrene.

## Reference

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
