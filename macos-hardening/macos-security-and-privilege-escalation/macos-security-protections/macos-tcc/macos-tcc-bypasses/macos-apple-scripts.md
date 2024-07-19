# macOS Apple Scripts

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

## Apple Scripts

Це мова сценаріїв, що використовується для автоматизації завдань **взаємодії з віддаленими процесами**. Вона дозволяє досить легко **просити інші процеси виконувати певні дії**. **Шкідливе ПЗ** може зловживати цими функціями для зловживання функціями, експортованими іншими процесами.\
Наприклад, шкідливе ПЗ може **впроваджувати довільний JS код у відкриті сторінки браузера**. Або **автоматично натискати** деякі дозволи, запитані у користувача;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ось кілька прикладів: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Знайдіть більше інформації про шкідливе ПЗ, що використовує applescripts [**тут**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple скрипти можуть бути легко "**скомпільовані**". Ці версії можуть бути легко "**декомпільовані**" за допомогою `osadecompile`

Однак ці скрипти також можуть бути **експортовані як "Тільки для читання"** (через опцію "Експортувати..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
і в цьому випадку вміст не може бути декомпільований навіть за допомогою `osadecompile`

Однак все ще існують деякі інструменти, які можна використовувати для розуміння таких виконуваних файлів, [**прочитайте це дослідження для отримання додаткової інформації**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Інструмент [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) з [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) буде дуже корисним для розуміння того, як працює скрипт.

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
