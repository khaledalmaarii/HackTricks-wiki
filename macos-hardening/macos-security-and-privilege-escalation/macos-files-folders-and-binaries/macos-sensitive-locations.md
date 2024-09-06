# macOS Sensitiewe Lokasies & Interessante Daemons

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**intekening planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Wagwoorde

### Skadu Wagwoorde

Skadu wagwoord word gestoor met die gebruiker se konfigurasie in plists geleë in **`/var/db/dslocal/nodes/Default/users/`**.\
Die volgende eenlyn kan gebruik word om **alle inligting oor die gebruikers** (insluitend hash inligting) te dump: 

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Scripts soos hierdie**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) of [**hierdie**](https://github.com/octomagon/davegrohl.git) kan gebruik word om die hash na **hashcat** **formaat** te transformeer.

'n Alternatiewe een-liner wat die kredensiale van alle nie-diens rekeninge in hashcat formaat `-m 7100` (macOS PBKDF2-SHA512) sal dump: 

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Sleutelsak Dump

Let daarop dat wanneer die sekuriteit-binary gebruik word om **die wagwoorde ontcijfer** te dump, verskeie vrae die gebruiker sal vra om hierdie operasie toe te laat.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Op grond van hierdie kommentaar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) lyk dit of hierdie gereedskap nie meer werk in Big Sur nie.
{% endhint %}

### Keychaindump Oorsig

'n Gereedskap genaamd **keychaindump** is ontwikkel om wagwoorde uit macOS sleutelhouers te onttrek, maar dit ondervind beperkings op nuwer macOS weergawes soos Big Sur, soos aangedui in 'n [bespreking](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Die gebruik van **keychaindump** vereis dat die aanvaller toegang verkry en bevoegdhede tot **root** verhoog. Die gereedskap benut die feit dat die sleutelhouer standaard ontgrendel is by gebruikersaanmelding vir gerief, wat toepassings toelaat om dit te benader sonder om die gebruiker se wagwoord herhaaldelik te vereis. As 'n gebruiker egter kies om hul sleutelhouer na elke gebruik te sluit, word **keychaindump** ondoeltreffend.

**Keychaindump** werk deur 'n spesifieke proses genaamd **securityd** te teiken, wat deur Apple beskryf word as 'n daemon vir magtiging en kriptografiese operasies, wat noodsaaklik is vir toegang tot die sleutelhouer. Die onttrekkingsproses behels die identifisering van 'n **Master Key** wat afgelei is van die gebruiker se aanmeldwagwoord. Hierdie sleutel is noodsaaklik om die sleutelhouer-lêer te lees. Om die **Master Key** te vind, skandeer **keychaindump** die geheuehoop van **securityd** met behulp van die `vmmap` opdrag, op soek na potensiële sleutels binne areas wat as `MALLOC_TINY` gemerk is. Die volgende opdrag word gebruik om hierdie geheue-lokasies te ondersoek:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Na die identifisering van potensiële meester sleutels, **keychaindump** soek deur die hoop vir 'n spesifieke patroon (`0x0000000000000018`) wat 'n kandidaat vir die meester sleutel aandui. Verdere stappe, insluitend deobfuscation, is nodig om hierdie sleutel te benut, soos uiteengesit in **keychaindump**'s bronkode. Ontleders wat op hierdie gebied fokus, moet oplet dat die belangrike data vir die ontsleuteling van die sleutelring binne die geheue van die **securityd** proses gestoor is. 'n Voorbeeldopdrag om **keychaindump** te loop is:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word om die volgende tipes inligting uit 'n OSX sleutelketting op 'n forensies-gesonde manier te onttrek:

* Gehashde Sleutelketing wagwoord, geskik vir kraken met [hashcat](https://hashcat.net/hashcat/) of [John the Ripper](https://www.openwall.com/john/)
* Internet Wagwoorde
* Generiese Wagwoorde
* Privaat Sleutels
* Publieke Sleutels
* X509 Sertifikate
* Veilige Aantekeninge
* Appleshare Wagwoorde

Gegewe die sleutelketing ontgrendel wagwoord, 'n meester sleutel verkry met behulp van [volafox](https://github.com/n0fate/volafox) of [volatility](https://github.com/volatilityfoundation/volatility), of 'n ontgrendel lêer soos SystemKey, sal Chainbreaker ook platteks wagwoorde verskaf.

Sonder een van hierdie metodes om die Sleutelketing te ontgrendel, sal Chainbreaker al die ander beskikbare inligting vertoon.

#### **Dump sleutelketing sleutels**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump sleutelring sleutels (met wagwoorde) met SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump sleutelring sleutels (met wagwoorde) om die hash te kraak**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump sleutelring sleutels (met wagwoorde) met geheue-aflaai**

[Volg hierdie stappe](../#dumping-memory-with-osxpmem) om 'n **geheue-aflaai** uit te voer
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump sleutelring sleutels (met wagwoorde) met die gebruiker se wagwoord**

As jy die gebruiker se wagwoord ken, kan jy dit gebruik om **sleutelrings wat aan die gebruiker behoort te dump en te ontsleutel**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Die **kcpassword** lêer is 'n lêer wat die **gebruikers se aanmeldwagwoord** bevat, maar slegs as die stelselaanvaarder **outomatiese aanmelding** geaktiveer het. Daarom sal die gebruiker outomaties aangemeld word sonder om vir 'n wagwoord gevra te word (wat nie baie veilig is nie).

Die wagwoord word in die lêer **`/etc/kcpassword`** xored met die sleutel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. As die gebruiker se wagwoord langer is as die sleutel, sal die sleutel hergebruik word.\
Dit maak die wagwoord redelik maklik om te herstel, byvoorbeeld met behulp van skripte soos [**hierdie een**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Jy kan die Kennisgewings data vind in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Die meeste van die interessante inligting gaan in **blob** wees. So jy sal daardie inhoud moet **onttrek** en dit moet **omskakel** na **mens** **leesbaar** of gebruik **`strings`**. Om toegang te verkry kan jy doen: 

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Aantekeninge

Die gebruikers **aantekeninge** kan gevind word in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Voorkeure

In macOS toepassings is voorkeure geleë in **`$HOME/Library/Preferences`** en in iOS is dit in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.&#x20;

In macOS kan die cli-gereedskap **`defaults`** gebruik word om die **Voorkeur lêer** te **wysig**.

**`/usr/sbin/cfprefsd`** eis die XPC dienste `com.apple.cfprefsd.daemon` en `com.apple.cfprefsd.agent` en kan geroep word om aksies soos om voorkeure te wysig, uit te voer.

## Stelselnotasies

### Darwin Notasies

Die hoofdaemon vir notasies is **`/usr/sbin/notifyd`**. Om notasies te ontvang, moet kliënte registreer deur die `com.apple.system.notification_center` Mach-poort (kontroleer dit met `sudo lsmp -p <pid notifyd>`). Die daemon is konfigureerbaar met die lêer `/etc/notify.conf`.

Die name wat vir notasies gebruik word, is unieke omgekeerde DNS-notasies en wanneer 'n notasie na een van hulle gestuur word, sal die kliënt(e) wat aangedui het dat hulle dit kan hanteer, dit ontvang.

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
### Verspreide Kennisgewing Sentrum

Die **Verspreide Kennisgewing Sentrum** waarvan die hoof binêre **`/usr/sbin/distnoted`** is, is 'n ander manier om kennisgewings te stuur. Dit stel 'n paar XPC dienste bloot en dit voer 'n paar kontroles uit om te probeer om kliënte te verifieer.

### Apple Push Kennisgewings (APN)

In hierdie geval kan toepassings registreer vir **onderwerpe**. Die kliënt sal 'n token genereer deur Apple se bedieners te kontak deur middel van **`apsd`**.\
Dan sal verskaffers ook 'n token genereer en in staat wees om met Apple se bedieners te verbind om boodskappe aan die kliënte te stuur. Hierdie boodskappe sal plaaslik deur **`apsd`** ontvang word wat die kennisgewing aan die toepassing wat daarop wag, sal oordra.

Die voorkeure is geleë in `/Library/Preferences/com.apple.apsd.plist`.

Daar is 'n plaaslike databasis van boodskappe geleë in macOS in `/Library/Application\ Support/ApplePushService/aps.db` en in iOS in `/var/mobile/Library/ApplePushService`. Dit het 3 tabelle: `incoming_messages`, `outgoing_messages` en `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Dit is ook moontlik om inligting oor die daemon en verbindings te verkry met:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

Hierdie is kennisgewings wat die gebruiker op die skerm moet sien:

* **`CFUserNotification`**: Hierdie API bied 'n manier om 'n pop-up met 'n boodskap op die skerm te wys.
* **Die Bulletin Board**: Dit wys in iOS 'n banner wat verdwyn en in die Kennisgewing Sentrum gestoor sal word.
* **`NSUserNotificationCenter`**: Dit is die iOS bulletin board in MacOS. Die databasis met die kennisgewings is geleë in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

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
