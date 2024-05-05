# macOS Bezbednost & Eskalacija Privilegija

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru kako biste komunicirali sa iskusnim hakerima i lovcima na bagove!

**Hakerski Uvidi**\
Uključite se u sadržaj koji istražuje uzbuđenje i izazove hakovanja

**Vesti o Hakovanju u Realnom Vremenu**\
Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu

**Najnovije Najave**\
Budite informisani o najnovijim nagradama za pronalaženje bagova i bitnim ažuriranjima platformi

**Pridružite nam se na** [**Discord-u**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

## Osnovno o MacOS-u

Ako niste upoznati sa macOS-om, trebalo bi da počnete sa učenjem osnova macOS-a:

* Posebne macOS **datoteke i dozvole:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Uobičajeni macOS **korisnici**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **Arhitektura** jezgra

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Uobičajene macOS **mrežne usluge i protokoli**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Da biste preuzeli `tar.gz` promenite URL kao što je [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) u [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

U kompanijama **macOS** sistemi verovatno će biti **upravljani MDM-om**. Stoga, sa perspektive napadača je zanimljivo znati **kako to funkcioniše**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspekcija, Debugovanje i Faziranje

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Zaštite MacOS Bezbednosti

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Napadna Površina

### Dozvole Datoteka

Ako **proces koji se izvršava kao root piše** datoteku kojom može upravljati korisnik, korisnik bi to mogao zloupotrebiti za **eskalaciju privilegija**.\
Ovo se može desiti u sledećim situacijama:

* Datoteka koja se koristi već je kreirana od strane korisnika (vlasništvo korisnika)
* Datoteka koja se koristi je upisiva od strane korisnika zbog grupe
* Datoteka koja se koristi je unutar direktorijuma koji je vlasništvo korisnika (korisnik bi mogao kreirati datoteku)
* Datoteka koja se koristi je unutar direktorijuma koji je vlasništvo root-a, ali korisnik ima pristup pisanju nad njim zbog grupe (korisnik bi mogao kreirati datoteku)

Mogućnost **kreiranja datoteke** koja će biti **korišćena od strane root-a**, omogućava korisniku da **iskoristi njen sadržaj** ili čak kreira **simboličke veze/fizičke veze** da je usmeri na drugo mesto.

Za ovakve ranjivosti ne zaboravite da **proverite ranjive `.pkg` instalere**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Ekstenzija Datoteke & Aplikacije za Obradu URL šema

Čudne aplikacije registrovane preko ekstenzija datoteka mogu biti zloupotrebljene i različite aplikacije mogu biti registrovane da otvore specifične protokole

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Eskalacija Privilegija

U macOS-u **aplikacije i binarni fajlovi mogu imati dozvole** za pristup fasciklama ili podešavanjima koja ih čine privilegovanim u odnosu na druge.

Stoga, napadač koji želi uspešno kompromitovati macOS mašinu će morati da **eskalira svoje TCC privilegije** (ili čak **zaobiđe SIP**, u zavisnosti od svojih potreba).

Ove privilegije obično se dodeljuju u obliku **ovlašćenja** sa kojima je aplikacija potpisana, ili aplikacija može zatražiti neke pristupe i nakon što ih **korisnik odobri** mogu se naći u **TCC bazama podataka**. Drugi način na koji proces može dobiti ove privilegije je ako je **potomak procesa** sa tim **privilegijama** jer se obično **nasleđuju**.

Pratite ove linkove da biste pronašli različite načine za [**eskalciju privilegija u TCC-u**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), za [**zaobilaženje TCC-a**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) i kako je u prošlosti [**SIP zaobiđen**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Tradicionalna Eskalacija Privilegija

Naravno, sa perspektive timova za crveno testiranje trebalo bi da vas zanima i eskalacija do root-a. Proverite sledeći post za neke smernice:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Reference

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru kako biste komunicirali sa iskusnim hakerima i lovcima na bagove!

**Hacking Insights**\
Uključite se u sadržaj koji istražuje uzbuđenje i izazove hakovanja

**Vesti o hakovanju u realnom vremenu**\
Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu

**Poslednje objave**\
Budite informisani o najnovijim nagradama za pronalaženje bagova i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discord-u**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
