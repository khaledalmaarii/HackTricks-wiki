# macOS Wrażliwe Lokalizacje i Interesujące Daemony

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Hasła

### Hasła Cieni

Hasło cienia jest przechowywane w konfiguracji użytkownika w plikach plist znajdujących się w **`/var/db/dslocal/nodes/Default/users/`**.\
Następujący oneliner może być użyty do wycieku **wszystkich informacji o użytkownikach** (w tym informacji o haszach):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Skrypty takie jak ten**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) lub [**ten**](https://github.com/octomagon/davegrohl.git) mogą być używane do przekształcenia hasha do **formatu hashcat**.

Alternatywna jednolinijkowa komenda, która wypisze dane uwierzytelniające wszystkich kont niebędących kontami usługowymi w formacie hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Wydobycie Keychain

Należy pamiętać, że podczas korzystania z binariów security do **wydobycia zdekodowanych haseł**, użytkownik będzie proszony o zezwolenie na tę operację.
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
Na podstawie tego komentarza [juuso/keychaindump#10 (komentarz)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) wygląda na to, że te narzędzia już nie działają w Big Sur.
{% endhint %}

### Przegląd Keychaindump

Narzędzie o nazwie **keychaindump** zostało opracowane do wydobywania haseł z keychainów macOS, ale napotyka ograniczenia na nowszych wersjach macOS, takich jak Big Sur, jak wskazano w [dyskusji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Użycie **keychaindump** wymaga, aby atakujący uzyskał dostęp i eskalował uprawnienia do **roota**. Narzędzie wykorzystuje fakt, że keychain jest domyślnie odblokowany po zalogowaniu użytkownika dla wygody, umożliwiając aplikacjom dostęp do niego bez konieczności wielokrotnego wprowadzania hasła użytkownika. Jednak jeśli użytkownik zdecyduje się blokować swój keychain po każdym użyciu, **keychaindump** staje się nieskuteczny.

**Keychaindump** działa poprzez celowanie w określony proces o nazwie **securityd**, opisany przez Apple jako demon do autoryzacji i operacji kryptograficznych, kluczowy do dostępu do keychaina. Proces ekstrakcji polega na zidentyfikowaniu **klucza głównego** pochodzącego z hasła logowania użytkownika. Ten klucz jest niezbędny do odczytywania pliku keychain. Aby zlokalizować **klucz główny**, **keychaindump** skanuje stertę pamięci **securityd** za pomocą polecenia `vmmap`, szukając potencjalnych kluczy w obszarach oznaczonych jako `MALLOC_TINY`. Do inspekcji tych lokalizacji pamięci używane jest następujące polecenie:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Po zidentyfikowaniu potencjalnych kluczy głównych, **keychaindump** przeszukuje sterty w poszukiwaniu określonego wzorca (`0x0000000000000018`), który wskazuje na kandydata na klucz główny. Aby wykorzystać ten klucz, konieczne są dodatkowe kroki, w tym deobfuskacja, zgodnie z opisem w kodzie źródłowym **keychaindump**. Analitycy skupiający się na tym obszarze powinni zauważyć, że istotne dane do odszyfrowania keychain są przechowywane w pamięci procesu **securityd**. Przykładowe polecenie do uruchomienia **keychaindump** to:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) można użyć do wyodrębnienia następujących typów informacji z keychain'a OSX w sposób forensycznie poprawny:

* Zahaszowane hasło Keychain, odpowiednie do złamania za pomocą [hashcat](https://hashcat.net/hashcat/) lub [John the Ripper](https://www.openwall.com/john/)
* Hasła internetowe
* Hasła ogólne
* Klucze prywatne
* Klucze publiczne
* Certyfikaty X509
* Bezpieczne notatki
* Hasła Appleshare

Dzięki odblokowaniu hasła keychain'a, uzyskanemu kluczowi głównemu za pomocą [volafox](https://github.com/n0fate/volafox) lub [volatility](https://github.com/volatilityfoundation/volatility), lub plikowi odblokowującemu, takiemu jak SystemKey, Chainbreaker dostarczy również hasła w formie tekstu jawnego.

Bez jednej z tych metod odblokowania Keychain'a, Chainbreaker wyświetli wszystkie inne dostępne informacje.

#### **Wyciek kluczy keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Wyciek kluczy keychain (z hasłami) za pomocą SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Wyciek kluczy keychain (z hasłami) łamiąc skrót**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Wyciek kluczy keychain (z hasłami) za pomocą zrzutu pamięci**

[Postępuj zgodnie z tymi krokami](../#dumping-memory-with-osxpmem), aby wykonać **zrzut pamięci**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Wyciek kluczy keychain (z hasłami) za pomocą hasła użytkownika**

Jeśli znasz hasło użytkownika, możesz użyć go do **wycieku i odszyfrowania keychainów należących do użytkownika**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Plik **kcpassword** to plik przechowujący **hasło logowania użytkownika**, ale tylko jeśli właściciel systemu ma włączone **automatyczne logowanie**. W związku z tym użytkownik zostanie zalogowany automatycznie, bez konieczności podawania hasła (co nie jest zbyt bezpieczne).

Hasło jest przechowywane w pliku **`/etc/kcpassword`** zaszyfrowane operacją XOR przy użyciu klucza **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Jeśli hasło użytkownika jest dłuższe niż klucz, klucz będzie używany wielokrotnie.\
To sprawia, że odzyskanie hasła jest dość proste, na przykład przy użyciu skryptów takich jak [**ten**](https://gist.github.com/opshope/32f65875d45215c3677d). 

## Interesujące informacje w bazach danych

### Wiadomości
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Powiadomienia

Dane dotyczące powiadomień znajdziesz w `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Większość interesujących informacji będzie znajdować się w **blob**. Będziesz musiał **wyodrębnić** ten zawartość i **przekształcić** ją w formę **czytelną dla człowieka** lub użyć polecenia **`strings`**. Aby uzyskać do niej dostęp, wykonaj:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notatki

Notatki użytkowników można znaleźć w `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Preferencje

W aplikacjach macOS preferencje znajdują się w **`$HOME/Library/Preferences`**, a w systemie iOS w `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

W macOS narzędzie wiersza poleceń **`defaults`** może być użyte do **modyfikacji pliku preferencji**.

**`/usr/sbin/cfprefsd`** obsługuje usługi XPC `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i może być wywoływane do wykonywania działań, takich jak modyfikacja preferencji.

## Powiadomienia Systemowe

### Powiadomienia Darwin

Głównym demonem do obsługi powiadomień jest **`/usr/sbin/notifyd`**. Aby otrzymywać powiadomienia, klienci muszą zarejestrować się przez port Mach `com.apple.system.notification_center` (sprawdź je za pomocą `sudo lsmp -p <pid notifyd>`). Demon jest konfigurowalny za pomocą pliku `/etc/notify.conf`.

Nazwy używane do powiadomień są unikalnymi odwrotnymi notacjami DNS, a gdy powiadomienie jest wysyłane do jednego z nich, klient(y), które wskazały, że mogą je obsłużyć, je otrzymają.

Możliwe jest zrzucenie bieżącego stanu (i zobaczenie wszystkich nazw) wysyłając sygnał SIGUSR2 do procesu notifyd i odczytując wygenerowany plik: `/var/run/notifyd_<pid>.status`:
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
### Centrum powiadomień rozproszonych

**Centrum powiadomień rozproszonych**, którego głównym plikiem binarnym jest **`/usr/sbin/distnoted`**, to kolejny sposób wysyłania powiadomień. Udostępnia kilka usług XPC i wykonuje pewne sprawdzenia w celu weryfikacji klientów.

### Powiadomienia push Apple (APN)

W tym przypadku aplikacje mogą zarejestrować się dla **tematów**. Klient wygeneruje token kontaktując się z serwerami Apple'a poprzez **`apsd`**.\
Następnie dostawcy również wygenerują token i będą mogli połączyć się z serwerami Apple'a, aby wysyłać wiadomości do klientów. Te wiadomości zostaną lokalnie odebrane przez **`apsd`**, który przekaże powiadomienie do oczekującej na nie aplikacji.

Preferencje znajdują się w `/Library/Preferences/com.apple.apsd.plist`.

W systemie macOS istnieje lokalna baza danych wiadomości w `/Library/Application\ Support/ApplePushService/aps.db`, a w systemie iOS w `/var/mobile/Library/ApplePushService`. Baza ta zawiera 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Możliwe jest również uzyskanie informacji o daemonie i połączeniach za pomocą:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Powiadomienia użytkownika

To są powiadomienia, które użytkownik powinien zobaczyć na ekranie:

* **`CFUserNotification`**: Ta API umożliwia wyświetlenie na ekranie wyskakującego okienka z wiadomością.
* **Tablica ogłoszeń**: Pokazuje w iOS baner, który zniknie i zostanie przechowany w Centrum Powiadomień.
* **`NSUserNotificationCenter`**: To jest tablica ogłoszeń iOS w systemie MacOS. Baza danych z powiadomieniami znajduje się w `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`
