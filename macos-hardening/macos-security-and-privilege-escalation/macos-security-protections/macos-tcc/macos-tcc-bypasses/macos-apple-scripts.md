# macOS Сценарії Apple

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

## Сценарії Apple

Це мова сценаріїв, яка використовується для автоматизації завдань **взаємодії з віддаленими процесами**. Вона дозволяє досить легко **запитувати інші процеси виконувати певні дії**. **Шкідливе програмне забезпечення** може зловживати цими можливостями, щоб використовувати функції, експортовані іншими процесами.\
Наприклад, шкідливе програмне забезпечення може **впроваджувати довільний JS-код на відкриті сторінки браузера**. Або **автоматично клацати** деякі дозволи, запитані користувачем;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ось деякі приклади: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Знайдіть більше інформації про шкідливе програмне забезпечення, яке використовує скрипти Apple [**тут**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Скрипти Apple можуть бути легко "**компільовані**". Ці версії можуть бути легко "**декомпільовані**" за допомогою `osadecompile`

Однак ці скрипти також можуть бути **експортовані як "Тільки для читання"** (через опцію "Експорт..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
і в цьому випадку вміст не може бути декомпільований навіть за допомогою `osadecompile`

Однак є деякі інструменти, які можна використовувати для розуміння цих виконуваних файлів, [**прочитайте це дослідження для отримання додаткової інформації**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Інструмент [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) з [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) буде дуже корисним для розуміння того, як працює сценарій.

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити свою **компанію рекламовану в HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
