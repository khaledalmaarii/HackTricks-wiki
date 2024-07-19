# SmbExec/ScExec

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

## Як це працює

**Smbexec** - це інструмент, що використовується для віддаленого виконання команд на системах Windows, подібно до **Psexec**, але він уникає розміщення будь-яких шкідливих файлів на цільовій системі.

### Ключові моменти про **SMBExec**

- Він працює, створюючи тимчасову службу (наприклад, "BTOBTO") на цільовій машині для виконання команд через cmd.exe (%COMSPEC%), без скидання будь-яких бінарних файлів.
- Незважаючи на свій прихований підхід, він генерує журнали подій для кожної виконаної команди, пропонуючи форму неінтерактивної "оболонки".
- Команда для підключення за допомогою **Smbexec** виглядає так:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Виконання команд без бінарних файлів

- **Smbexec** дозволяє безпосереднє виконання команд через binPaths сервісу, усуваючи необхідність у фізичних бінарних файлах на цілі.
- Цей метод корисний для виконання одноразових команд на цільовій системі Windows. Наприклад, поєднання його з модулем `web_delivery` Metasploit дозволяє виконати зворотний Meterpreter payload, націлений на PowerShell.
- Створивши віддалений сервіс на машині атакуючого з binPath, налаштованим для виконання наданої команди через cmd.exe, можна успішно виконати payload, досягнувши зворотного зв'язку та виконання payload з прослуховувачем Metasploit, навіть якщо виникають помилки у відповіді сервісу.

### Приклад команд

Створення та запуск сервісу можна виконати за допомогою наступних команд:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

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
