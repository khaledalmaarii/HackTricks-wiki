# macOS Kernel i sistemski ekstenzije

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## XNU Kernel

**Srce macOS-a je XNU**, što znači "X is Not Unix". Ovaj kernel je suštinski sastavljen od **Mach mikrokernela** (o kojem će biti reči kasnije), **i** elemenata iz Berkeley Software Distribution (**BSD**). XNU takođe pruža platformu za **kernel drajvere putem sistema koji se zove I/O Kit**. XNU kernel je deo Darwin open source projekta, što znači da je **njegov izvorni kod slobodno dostupan**.

Sa stanovišta istraživača bezbednosti ili Unix programera, **macOS** može delovati prilično **slično** FreeBSD sistemu sa elegantnim grafičkim korisničkim interfejsom i mnoštvom prilagođenih aplikacija. Većina aplikacija razvijenih za BSD će se kompajlirati i pokretati na macOS-u bez potrebe za modifikacijama, jer su alati komandne linije koji su poznati Unix korisnicima prisutni u macOS-u. Međutim, zbog toga što XNU kernel inkorporira Mach, postoje neke značajne razlike između tradicionalnog Unix-sličnog sistema i macOS-a, a ove razlike mogu izazvati potencijalne probleme ili pružiti jedinstvene prednosti.

Izvorni kod otvorene verzije XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach je **mikrokernel** dizajniran da bude **kompatibilan sa UNIX-om**. Jedan od njegovih ključnih principa dizajna bio je da **minimalizuje** količinu **koda** koji se izvršava u **kernel** prostoru i umesto toga omogući mnoge tipične funkcije kernela, kao što su sistem datoteka, mreža i I/O, da se **izvršavaju kao zadaci na nivou korisnika**.

U XNU-u, Mach je **odgovoran za mnoge kritične operacije niskog nivoa** koje kernel obično obavlja, kao što su raspoređivanje procesora, multitasking i upravljanje virtuelnom memorijom.

### BSD

XNU **kernel** takođe **inkorporira** značajnu količinu koda izvedenog iz projekta **FreeBSD**. Ovaj kod **se izvršava kao deo kernela zajedno sa Mach-om**, u istom adresnom prostoru. Međutim, FreeBSD kod unutar XNU-a može se značajno razlikovati od originalnog FreeBSD koda jer su bile potrebne modifikacije kako bi se osigurala njegova kompatibilnost sa Mach-om. FreeBSD doprinosi mnogim operacijama kernela, uključujući:

* Upravljanje procesima
* Obrada signala
* Osnovni mehanizmi bezbednosti, uključujući upravljanje korisnicima i grupama
* Infrastruktura sistemskih poziva
* TCP/IP stek i soketi
* Firewall i filtriranje paketa

Razumevanje interakcije između BSD-a i Mach-a može biti kompleksno, zbog njihovih različitih konceptualnih okvira. Na primer, BSD koristi procese kao svoje osnovne izvršne jedinice, dok Mach funkcioniše na osnovu niti. Ova razlika se usklađuje u XNU-u tako što se **svakom BSD procesu dodeljuje Mach zadatak** koji sadrži tačno jednu Mach nit. Kada se koristi BSD-ov fork() sistemski poziv, BSD kod unutar kernela koristi Mach funkcije za kreiranje zadatka i strukture niti.

Pored toga, **Mach i BSD održavaju različite modele bezbednosti**: **Mach-ov** model bezbednosti se zasniva na **pravima porta**, dok BSD-ov model bezbednosti funkcioniše na osnovu **vlasništva procesa**. Razlike između ova dva modela povremeno su rezultirale ranjivostima lokalnog eskalacije privilegija. Osim tipičnih sistemskih poziva, postoje i **Mach zamke koje omogućavaju programima u prostoru korisničkog prostora da komuniciraju sa kernelom**. Ovi različiti elementi zajedno čine složenu, hibridnu arhitekturu macOS kernela.

### I/O Kit - Drajveri

I/O Kit je open-source, objektno-orijentisani **okvir za upravljače uređaja** u XNU kernelu, koji se bavi **dinamičkim učitavanjem drajvera uređaja**. Omogućava dodavanje modularnog koda u kernel u hodu, podržavajući različit hardver.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Interprocesna komunikacija

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

**Kernelcache** je **prekompilirana i prelinkovana verzija XNU kernela**, zajedno sa osnovnim drajverima uređaja i kernel ekstenzijama. Čuva se u **komprimiranom** formatu i dekompresuje u memoriju tokom procesa pokretanja. Kernelcache omogućava **brže vreme pokretanja** jer ima verziju kernela i ključnih drajvera spremnih za pokretanje, smanjujući vreme i resurse koji bi inače bili potrošeni na dinamičko učitavanje i povezivanje ovih komponenti tokom pokretanja.

U iOS-u se nalazi u **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, a u macOS-u ga možete pronaći sa **`find / -name kernelcache 2>/dev/null`**

#### IMG4

IMG4 format datoteke je kontejnerski format koji se koristi od strane Apple-a u svojim iOS i macOS uređajima za sigurno **skladištenje i proveru firmware** komponenti (poput **kernelcache**-a). IMG4 format uključuje zaglavlje i nekoliko oznaka koje inkapsuliraju različite delove podataka, uključujući stvarni payload (poput kernela ili bootloadera), potpis i skup manifestnih svojstava. Format podržava kriptografsku verifikaciju, što omogućava uređaju da potvrdi autentičnost i integritet firmware komponente pre njene izvršne.

Obično je sastavljen od sledećih komponenti:

* **Payload (IM4P)**:
* Često komprimiran (LZFSE4, LZSS, ...)
* Opciono šifrovan
* **Manifest (IM4M)**:
* Sadrži potpis
* Dodatni ključ/vrednost rečnik
* **Restore Info (IM4R)**:
* Takođe poznat kao APNonce
* Onemogućava reprodukovanje nekih ažuriranja
* OPCIONALNO: Obično se ne nalazi

Dekompresirajte Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Simboli kernel keša

Ponekad Apple objavljuje **kernel keš** sa **simbolima**. Možete preuzeti neke firmvere sa simbolima prateći linkove na [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

To su Apple **firmveri** koje možete preuzeti sa [**https://ipsw.me/**](https://ipsw.me/). Pored ostalih datoteka, sadržaće i **kernel keš**.\
Da biste **izvukli** datoteke, jednostavno ih možete **otpakovati**.

Nakon otpakivanja firmvera, dobićete datoteku poput: **`kernelcache.release.iphone14`**. Ona je u formatu **IMG4**, a zanimljive informacije možete izvući pomoću:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Možete proveriti izvučeni kernelcache za simbole pomoću: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Sada možemo **izvući sve ekstenzije** ili **onu koja vas zanima:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## macOS Kernel ekstenzije

macOS je **izuzetno restriktivan u učitavanju Kernel ekstenzija** (.kext) zbog visokih privilegija koje će kod imati prilikom izvršavanja. Zapravo, prema zadanim podešavanjima je praktično nemoguće (osim ako se ne pronađe zaobilaznica).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS Sistemsko proširenje

Umesto korišćenja Kernel ekstenzija, macOS je kreirao Sistemsko proširenje koje pruža API-je na nivou korisnika za interakciju sa kernelom. Na ovaj način, programeri mogu izbeći korišćenje kernel ekstenzija.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Reference

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
