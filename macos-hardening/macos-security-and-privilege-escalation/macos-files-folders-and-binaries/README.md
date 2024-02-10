# macOS Fajlovi, Folderi, Binarni fajlovi i Memorija

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Hijerarhija fajlova

* **/Applications**: Instalirane aplikacije bi trebalo da se nalaze ovde. Svi korisnici će imati pristup njima.
* **/bin**: Binarni fajlovi komandne linije
* **/cores**: Ako postoji, koristi se za čuvanje core dump-ova
* **/dev**: Sve se tretira kao fajl, pa možete videti hardverske uređaje ovde.
* **/etc**: Konfiguracioni fajlovi
* **/Library**: Mnogo poddirektorijuma i fajlova vezanih za postavke, keširanje i logove se mogu naći ovde. Postoji Library folder u root-u i u svakom korisničkom direktorijumu.
* **/private**: Nedokumentovano, ali mnogi od pomenutih foldera su simboličke veze ka private direktorijumu.
* **/sbin**: Bitni sistemski binarni fajlovi (vezani za administraciju)
* **/System**: Fajl za pokretanje OS X-a. Ovde ćete uglavnom naći samo Apple specifične fajlove (ne treće strane).
* **/tmp**: Fajlovi se brišu nakon 3 dana (to je soft link ka /private/tmp)
* **/Users**: Home direktorijum za korisnike.
* **/usr**: Konfiguracioni i sistemski binarni fajlovi
* **/var**: Log fajlovi
* **/Volumes**: Montirani drajvovi će se pojaviti ovde.
* **/.vol**: Pokretanjem `stat a.txt` dobijate nešto kao `16777223 7545753 -rw-r--r-- 1 username wheel ...` gde je prvi broj ID broj volumena gde se fajl nalazi, a drugi broj je inode broj. Možete pristupiti sadržaju ovog fajla putem /.vol/ sa tim informacijama pokretanjem `cat /.vol/16777223/7545753`

### Folderi aplikacija

* **Sistemski programi** se nalaze pod `/System/Applications`
* **Instalirane** aplikacije obično se instaliraju u `/Applications` ili u `~/Applications`
* **Podaci aplikacije** se mogu naći u `/Library/Application Support` za aplikacije koje se pokreću kao root i `~/Library/Application Support` za aplikacije koje se pokreću kao korisnik.
* **Demoni** trećih strana aplikacija koji **mora da se pokreću kao root** obično se nalaze u `/Library/PrivilegedHelperTools/`
* **Sandbox** aplikacije su mapirane u folder `~/Library/Containers`. Svaka aplikacija ima folder nazvan prema bundle ID-u aplikacije (`com.apple.Safari`).
* **Kernel** se nalazi u `/System/Library/Kernels/kernel`
* **Apple-ovi kernel ekstenzije** se nalaze u `/System/Library/Extensions`
* **Kernel ekstenzije trećih strana** se čuvaju u `/Library/Extensions`

### Fajlovi sa osetljivim informacijama

macOS čuva informacije kao što su lozinke na nekoliko mesta:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Ranjivi pkg instalateri

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X Specifične Ekstenzije

* **`.dmg`**: Apple Disk Image fajlovi su veoma česti za instalere.
* **`.kext`**: Moraju pratiti određenu strukturu i to je OS X verzija drajvera. (to je bundle)
* **`.plist`**: Takođe poznat kao property list, čuva informacije u XML ili binarnom formatu.
* Može biti XML ili binarni. Binarni se mogu čitati sa:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Apple aplikacije koje prate strukturu direktorijuma (To je bundle).
* **`.dylib`**: Dinamičke biblioteke (kao Windows DLL fajlovi)
* **`.pkg`**: Isti su kao xar (eXtensible Archive format). Komanda installer se može koristiti za instaliranje sadržaja ovih fajlova.
* **`.DS_Store`**: Ovaj fajl se nalazi u svakom direktorijumu, čuva atribute i prilagođavanja direktorijuma.
* **`.Spotlight-V100`**: Ovaj folder se pojavljuje na root direktorijumu svakog volumena na sistemu.
* **`.metadata_never_index`**: Ako se ovaj fajl nalazi na root-u volumena, Spotlight neće indeksirati taj volumen.
* **`.noindex`**: Fajlovi i folderi sa ovom ekstenzijom neće biti indeksirani od strane Spotlight-a.

### macOS Bundle-ovi

Bundle je **direktorijum** koji **izgleda kao objekat u Finder-u** (primer Bundle-a su fajlovi `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Deljena Keš Memorija

Na macOS-u (i iOS-u) sve deljene sistemske biblioteke, poput framework-a i dylib-a, su **kombinovane u jedan fajl**, nazvan **dyld deljena keš memorija**. Ovo poboljšava performanse, jer se kod može učitati brže.

Slično kao dyld deljena keš memorija, kernel i kernel ekstenzije su takođe kompajlirane u kernel keš, koji se učitava prilikom pokretanja.

Da biste izdvojili biblioteke iz jednog fajla dylib deljene keš memorije, bilo je moguće koristiti binarni fajl [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) koji možda ne radi više, ali takođe možete koristiti [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

U starijim verzijama možda ćete moći pronaći **deljenu keš memoriju** u **`/System/Library/dyld/`**.

Na iOS-u ih možete pronaći u **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Imajte na umu da čak i ako alat `dyld_shared_cache_util` ne radi, možete proslediti **deljenu dyld binarnu datoteku Hopper-u** i Hopper će moći da identifikuje sve biblioteke i omogući vam da **izaberete koju** želite da istražite:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Posebne dozvole za datoteke

### Dozvole za direktorijume

U **direktorijumu**, **čitanje** omogućava da ga **izlistate**, **pisanje** omogućava da **brišete** i **pišete** datoteke u njemu, a **izvršavanje** omogućava da **pretražujete** direktorijum. Dakle, na primer, korisnik sa **dozvolom za čitanje nad datotekom** unutar direktorijuma gde **nema dozvolu za izvršavanje** **neće moći da pročita** datoteku.

### Modifikatori zastavica

Postoje neke zastavice koje se mogu postaviti u datotekama i koje će promeniti ponašanje datoteke. Možete **proveriti zastavice** datoteka unutar direktorijuma sa `ls -lO /putanja/direktorijum`

* **`uchg`**: Poznata kao zastavica **uchange** će **onemogućiti bilo koju akciju** promene ili brisanja **datoteke**. Da biste je postavili, koristite: `chflags uchg file.txt`
* Korisnik sa privilegijama **root** može **ukloniti zastavicu** i izmeniti datoteku
* **`restricted`**: Ova zastavica čini da datoteka bude **zaštićena od SIP** (ne možete dodati ovu zastavicu datoteci).
* **`Sticky bit`**: Ako direktorijum ima sticky bit, **samo** vlasnik direktorijuma ili root mogu preimenovati ili izbrisati datoteke. Obično se postavlja na /tmp direktorijum da bi se sprečilo obične korisnike da brišu ili premeste datoteke drugih korisnika.

### **ACL datoteke**

ACL datoteke sadrže **ACE** (Access Control Entries) gde se mogu dodeliti **detaljnije dozvole** različitim korisnicima.

Moguće je dodeliti **direktorijumu** sledeće dozvole: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
I datoteci: `read`, `write`, `append`, `execute`.

Kada datoteka sadrži ACL, **naći ćete "+" prilikom listanja dozvola kao što je prikazano u**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Možete **pročitati ACL-ove** datoteke pomoću:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Možete pronaći **sve datoteke sa ACL-ovima** sa (ovo je veeeeeoma sporo):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Resursni viljuške | macOS ADS

Ovo je način dobijanja **Alternativnih podataka u MacOS** mašinama. Možete sačuvati sadržaj unutar proširenog atributa nazvanog **com.apple.ResourceFork** unutar fajla tako što ćete ga sačuvati u **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Možete **pronaći sve datoteke koje sadrže ovaj prošireni atribut** sa:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Univerzalni binarni i** Mach-o format

Binarni fajlovi na Mac OS-u obično su kompajlirani kao **univerzalni binarni**. **Univerzalni binarni** mogu **podržavati više arhitektura u istom fajlu**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Dumpovanje memorije na macOS-u

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Kategorija rizičnih fajlova na Mac OS-u

Direktorijum `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` je mesto gde se čuva informacija o **riziku povezanom sa različitim ekstenzijama fajlova**. Ovaj direktorijum kategorizuje fajlove u različite nivoe rizika, što utiče na to kako Safari obrađuje ove fajlove prilikom preuzimanja. Kategorije su sledeće:

- **LSRiskCategorySafe**: Fajlovi u ovoj kategoriji se smatraju **potpuno bezbednim**. Safari će automatski otvoriti ove fajlove nakon što budu preuzeti.
- **LSRiskCategoryNeutral**: Ovi fajlovi nemaju upozorenja i **ne otvaraju se automatski** u Safariju.
- **LSRiskCategoryUnsafeExecutable**: Fajlovi u ovoj kategoriji **pokreću upozorenje** koje ukazuje da je fajl aplikacija. Ovo je sigurnosna mera koja upozorava korisnika.
- **LSRiskCategoryMayContainUnsafeExecutable**: Ova kategorija je namenjena fajlovima, poput arhiva, koji mogu sadržati izvršne fajlove. Safari će **pokrenuti upozorenje** osim ako ne može da potvrdi da su svi sadržaji bezbedni ili neutralni.

## Log fajlovi

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Sadrži informacije o preuzetim fajlovima, poput URL-a sa kog su preuzeti.
* **`/var/log/system.log`**: Glavni log za OSX sisteme. com.apple.syslogd.plist je odgovoran za izvršavanje syslogginga (možete proveriti da li je onemogućen tražeći "com.apple.syslogd" u `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Ovo su Apple System Logs koji mogu sadržati zanimljive informacije.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Čuva nedavno pristupljene fajlove i aplikacije putem "Finder"-a.
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Čuva stavke koje se pokreću prilikom pokretanja sistema.
* **`$HOME/Library/Logs/DiskUtility.log`**: Log fajl za DiskUtility aplikaciju (informacije o drajvovima, uključujući USB uređaje).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Podaci o bežičnim pristupnim tačkama.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista deaktiviranih daemon-a.

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
