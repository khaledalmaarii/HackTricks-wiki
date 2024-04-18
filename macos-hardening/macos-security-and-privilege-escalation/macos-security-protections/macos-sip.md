# macOS SIP

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark-web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **stealer malvera**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb stranicu i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

## **Osnovne informacije**

**Zaštita integriteta sistema (SIP)** u macOS-u je mehanizam dizajniran da spreči čak i najprivilegovanije korisnike da vrše neovlašćene promene u ključnim sistemskim fasciklama. Ova funkcija igra ključnu ulogu u održavanju integriteta sistema ograničavanjem radnji poput dodavanja, izmene ili brisanja fajlova u zaštićenim oblastima. Primarne fascikle zaštićene od strane SIP-a uključuju:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Pravila koja upravljaju ponašanjem SIP-a su definisana u konfiguracionom fajlu koji se nalazi na putanji **`/System/Library/Sandbox/rootless.conf`**. Unutar ovog fajla, putanje koje su prefiksirane zvezdicom (\*) označene su kao izuzeci od inače stroge SIP restrikcije.

Razmotrite sledeći primer:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ovaj odlomak implicira da iako SIP generalno obezbeđuje sigurnost direktorijuma **`/usr`**, postoje specifični poddirektorijumi (`/usr/libexec/cups`, `/usr/local` i `/usr/share/man`) gde su modifikacije dozvoljene, kako je naznačeno zvezdicom (\*) ispred njihovih putanja.

Da biste proverili da li je direktorijum ili fajl zaštićen SIP-om, možete koristiti komandu **`ls -lOd`** da proverite prisustvo zastave **`restricted`** ili **`sunlnk`**. Na primer:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
U ovom slučaju, zastava **`sunlnk`** označava da se direktorijum `/usr/libexec/cups` **ne može obrisati**, iako se fajlovi unutar njega mogu kreirati, menjati ili brisati.

S druge strane:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Evo, **`restricted`** zastava ukazuje da je direktorijum `/usr/libexec` zaštićen SIP-om. U SIP-zaštićenom direktorijumu, datoteke se ne mogu kreirati, menjati ili brisati.

Osim toga, ako datoteka sadrži atribut **`com.apple.rootless`** prošireni **atribut**, ta će datoteka takođe biti **zaštićena SIP-om**.

**SIP takođe ograničava druge root akcije** kao što su:

* Učitavanje nepoverenih kernel ekstenzija
* Dobijanje task-portova za Apple-potpisane procese
* Menjanje NVRAM promenljivih
* Dozvoljavanje kernel debagovanja

Opcije se održavaju u nvram promenljivoj kao bitflag (`csr-active-config` na Intelu i `lp-sip0` se čita iz podignutog Device Tree-a za ARM). Možete pronaći zastave u XNU izvornom kodu u `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (1189).png" alt=""><figcaption></figcaption></figure>

### Stanje SIP-a

Možete proveriti da li je SIP omogućen na vašem sistemu pomoću sledeće komande:
```bash
csrutil status
```
Ako treba da onemogućite SIP, morate ponovo pokrenuti računar u režimu oporavka (pritisnite Command+R prilikom pokretanja), zatim izvršite sledeću komandu:
```bash
csrutil disable
```
Ako želite da zadržite SIP omogućen, ali uklonite zaštitu od debagiranja, to možete učiniti sa:
```bash
csrutil enable --without debug
```
### Ostale Restrikcije

* **Zabranjuje učitavanje nepotpisanih kernel ekstenzija** (kexts), osiguravajući da samo proverene ekstenzije komuniciraju sa jezgrom sistema.
* **Sprečava debagovanje** macOS sistemskih procesa, čuvajući osnovne sistemskih komponente od neovlašćenog pristupa i modifikacija.
* **Inhibira alate** poput dtrace-a da inspiciraju sistemskih procesa, dodatno štiteći integritet rada sistema.

[**Saznajte više o SIP informacijama u ovom predavanju**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

## Bypass-ovi SIP-a

Bypass-ovanje SIP-a omogućava napadaču da:

* **Pristupi korisničkim podacima**: Čita osetljive korisničke podatke poput mejlova, poruka i istorije Safarija sa svih korisničkih naloga.
* **TCC Bypass**: Direktno manipuliše TCC (Transparentnost, Saglasnost i Kontrola) bazom podataka kako bi dobio neovlašćen pristup web kameri, mikrofonu i drugim resursima.
* **Ustaničenje**: Postavlja malver na SIP-om zaštićene lokacije, čineći ga otpornim na uklanjanje, čak i uz privilegije root-a. Ovo takođe uključuje mogućnost manipulacije Alatom za uklanjanje malvera (MRT).
* **Učitavanje kernel ekstenzija**: Iako postoje dodatne zaštite, zaobilazak SIP-a pojednostavljuje proces učitavanja nepotpisanih kernel ekstenzija.

### Instalacioni Paketi

**Instalacioni paketi potpisani Apple-ovim sertifikatom** mogu zaobići njegove zaštite. To znači da će čak i paketi potpisani od strane standardnih programera biti blokirani ako pokušaju da modifikuju SIP-om zaštićene direktorijume.

### Nepostojeći SIP fajl

Potencijalna rupa u sistemu je ako je fajl naveden u **`rootless.conf` ali trenutno ne postoji**, može biti kreiran. Malver bi mogao iskoristiti ovo da **uspostavi postojanost** na sistemu. Na primer, zlonamerni program bi mogao kreirati .plist fajl u `/System/Library/LaunchDaemons` ako je naveden u `rootless.conf` ali nije prisutan.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Ovlašćenje **`com.apple.rootless.install.heritable`** omogućava zaobilaženje SIP-a
{% endhint %}

#### Shrootless

[**Istraživači iz ovog blog posta**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) otkrili su ranjivost u macOS mehanizmu zaštite sistema (SIP), nazvanu ranjivost 'Shrootless'. Ova ranjivost se fokusira na **`system_installd`** demon, koji ima ovlašćenje, **`com.apple.rootless.install.heritable`**, koje omogućava bilo kom od njegovih podprocesa da zaobiđe SIP-ove restrikcije fajl sistema.

**`system_installd`** demon će instalirati pakete koji su potpisani od strane **Apple-a**.

Istraživači su otkrili da tokom instalacije Apple-ovog potpisanog paketa (.pkg fajla), **`system_installd`** **pokreće** sve **post-install** skripte uključene u paket. Ove skripte se izvršavaju podrazumevanim shell-om, **`zsh`**, koji automatski **pokreće** komande iz **`/etc/zshenv`** fajla, ako postoji, čak i u neinteraktivnom režimu. Ovo ponašanje bi moglo biti iskorišćeno od strane napadača: kreiranjem zlonamerne `/etc/zshenv` datoteke i čekanjem da **`system_installd` pozove `zsh`**, mogli bi izvršiti proizvoljne operacije na uređaju.

Osim toga, otkriveno je da se **`/etc/zshenv` može koristiti kao opšta tehnika napada**, ne samo za zaobilaženje SIP-a. Svaki korisnički profil ima `~/.zshenv` fajl, koji se ponaša na isti način kao `/etc/zshenv` ali ne zahteva privilegije root-a. Ovaj fajl bi mogao biti korišćen kao mehanizam postojanosti, pokrećući se svaki put kada se `zsh` pokrene, ili kao mehanizam elevacije privilegija. Ako admin korisnik elevira na root koristeći `sudo -s` ili `sudo <komanda>`, `~/.zshenv` fajl bi bio pokrenut, efektivno elevirajući na root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

U [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) otkriveno je da isti **`system_installd`** proces može biti zloupotrebljen jer je stavljao **post-install skriptu unutar nasumično nazvanog foldera zaštićenog SIP-om unutar `/tmp`**. Stvar je u tome da **`/tmp` sam po sebi nije zaštićen SIP-om**, pa je bilo moguće **montirati** virtuelnu sliku na njega, zatim **instalater** bi stavio tamo **post-install skriptu**, **demontirao** virtuelnu sliku, **rekonstruisao** sve **foldere** i **dodao** **post-install** skriptu sa **payload-om** za izvršavanje.

#### [fsck\_cs alat](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Identifikovana je ranjivost gde je **`fsck_cs`** bio zaveden da ošteti ključni fajl, zbog svoje sposobnosti praćenja **simboličkih linkova**. Konkretno, napadači su kreirali link od _`/dev/diskX`_ do fajla `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Izvršavanje **`fsck_cs`** na _`/dev/diskX`_ dovelo je do oštećenja `Info.plist`. Integritet ovog fajla je vitalan za SIP (Sistemsku Zaštitu Integriteta) operativnog sistema, koji kontroliše učitavanje kernel ekstenzija. Jednom kada je oštećen, sposobnost SIP-a da upravlja isključenjima kernela je kompromitovana.

Komande za iskorišćavanje ove ranjivosti su:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Eksploatacija ove ranjivosti ima ozbiljne posledice. Datoteka `Info.plist`, koja je obično odgovorna za upravljanje dozvolama za jezgrene ekstenzije, postaje neefikasna. To uključuje nemogućnost crne liste određenih ekstenzija, poput `AppleHWAccess.kext`. Kao rezultat toga, sa mehanizmom kontrole SIP-a van funkcije, ova ekstenzija može biti učitana, dajući neovlašćen pristup čitanja i pisanja u RAM sistem.

#### [Montiranje preko SIP zaštićenih foldera](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Bilo je moguće montirati novi fajl sistem preko **SIP zaštićenih foldera kako bi se zaobišla zaštita**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Bypass upgradera (2016)](https://objective-see.org/blog/blog\_0x14.html)

Sistem je podešen da se pokrene sa ugrađene instalacione disk slike unutar `Install macOS Sierra.app` kako bi se ažurirao operativni sistem, koristeći `bless` alat. Komanda koja se koristi je sledeća:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bezbednost ovog procesa može biti ugrožena ako napadač promeni sliku nadogradnje (`InstallESD.dmg`) pre pokretanja. Strategija uključuje zamenu dinamičkog učitavača (dyld) sa zlonamernom verzijom (`libBaseIA.dylib`). Ova zamena rezultira izvršenjem koda napadača kada se pokrene instalater.

Kod napadača preuzima kontrolu tokom procesa nadogradnje, iskorišćavajući poverenje sistema u instalater. Napad se nastavlja tako što se menja slika `InstallESD.dmg` putem metode premeštanja, posebno ciljajući metodu `extractBootBits`. Ovo omogućava ubacivanje zlonamernog koda pre nego što se disk slika koristi.

Osim toga, unutar `InstallESD.dmg`, postoji `BaseSystem.dmg`, koji služi kao koreni fajl sistem koda nadogradnje. Ubacivanje dinamičke biblioteke u ovo omogućava zlonamernom kodu da funkcioniše unutar procesa sposobnog za menjanje fajlova na nivou OS-a, značajno povećavajući potencijal za kompromitovanje sistema.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

U ovom razgovoru sa [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), prikazano je kako **`systemmigrationd`** (koji može zaobići SIP) izvršava **bash** i **perl** skriptu, koja može biti zloupotrebljena putem okružnih promenljivih **`BASH_ENV`** i **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Ovlašćenje **`com.apple.rootless.install`** omogućava zaobilaženje SIP-a
{% endhint %}

Ovlašćenje `com.apple.rootless.install` poznato je po zaobilaženju Sistemskog Integriteta (SIP) na macOS-u. Ovo je posebno pomenuto u vezi sa [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

U ovom specifičnom slučaju, sistemski XPC servis smešten na lokaciji `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` poseduje ovo ovlašćenje. Ovo omogućava povezanom procesu da zaobiđe SIP ograničenja. Osim toga, ovaj servis posebno predstavlja metod koji dozvoljava premestanje fajlova bez primene bilo kakvih sigurnosnih mera.

## Zapečaćeni sistemske snimci

Zapečaćeni sistemske snimci su funkcija koju je Apple uveo u **macOS Big Sur (macOS 11)** kao deo mehanizma **Sistema Integriteta (SIP)** kako bi pružio dodatni sloj sigurnosti i stabilnosti sistema. Suštinski, to su samo za čitanje verzije volumena sistema.

Evo detaljnijeg pregleda:

1. **Nepromenljiv sistem**: Zapečaćeni sistemske snimci čine macOS sistemski volumen "nepromenljivim", što znači da ne može biti modifikovan. Ovo sprečava bilo kakve neovlašćene ili slučajne promene na sistemu koje bi mogle ugroziti sigurnost ili stabilnost sistema.
2. **Ažuriranja softvera sistema**: Kada instalirate ažuriranja ili nadogradnje macOS-a, macOS kreira novi sistemski snimak. Zatim macOS-ov startap volumen koristi **APFS (Apple File System)** da prebaci na ovaj novi snimak. Ceo proces primene ažuriranja postaje sigurniji i pouzdaniji jer sistem uvek može da se vrati na prethodni snimak ako nešto krene po zlu tokom ažuriranja.
3. **Razdvajanje podataka**: U kombinaciji sa konceptom razdvajanja volumena Podataka i Sistema koji je uveden u macOS Catalina, funkcija Zapečaćeni sistemske snimci se pobrinula da svi vaši podaci i podešavanja budu smešteni na odvojenom "**Podaci**" volumenu. Ova razdvajanja čini vaše podatke nezavisnim od sistema, što pojednostavljuje proces ažuriranja sistema i poboljšava sigurnost sistema.

Zapamtite da ovi snimci automatski upravlja macOS i ne zauzimaju dodatni prostor na disku, zahvaljujući mogućnostima deljenja prostora APFS-a. Takođe je važno napomenuti da su ovi snimci različiti od **Time Machine snimaka**, koji su korisnički dostupne rezerve celog sistema.

### Provera snimaka

Komanda **`diskutil apfs list`** prikazuje **detalje APFS volumena** i njihov raspored:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

U prethodnom izlazu je moguće videti da su **lokacije dostupne korisnicima** montirane pod `/System/Volumes/Data`.

Osim toga, **snimak macOS sistemskog volumena** je montiran u `/` i **zapečaćen** (kriptografski potpisan od strane OS-a). Dakle, ako se SIP zaobiđe i modifikuje, **OS se više neće podići**.

Takođe je moguće **proveriti da li je zapečaćenje omogućeno** pokretanjem:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Osim toga, snapshot disk je takođe montiran kao **samo za čitanje**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji krade informacije**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji krade informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
