# macOS Office Sandbox Bypasses

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

### Word Sandbox bypass via Launch Agents

Застосунок використовує **кастомний Sandbox** з правом **`com.apple.security.temporary-exception.sbpl`**, і цей кастомний пісочниця дозволяє записувати файли будь-де, якщо ім'я файлу починається з `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Отже, втеча була такою ж легкою, як **запис `plist`** LaunchAgent у `~/Library/LaunchAgents/~$escape.plist`.

Перевірте [**оригінальний звіт тут**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox bypass via Login Items and zip

Пам'ятайте, що з першої втечі Word може записувати довільні файли, ім'я яких починається з `~$`, хоча після виправлення попередньої уразливості не було можливості записувати в `/Library/Application Scripts` або в `/Library/LaunchAgents`.

Було виявлено, що зсередини пісочниці можливо створити **Login Item** (додатки, які виконуються, коли користувач входить в систему). Однак ці додатки **не виконуватимуться, якщо** вони **не підписані** і **неможливо додати аргументи** (тому ви не можете просто запустити зворотний шелл, використовуючи **`bash`**).

З попередньої втечі з пісочниці Microsoft відключив можливість запису файлів у `~/Library/LaunchAgents`. Однак було виявлено, що якщо ви помістите **zip-файл як Login Item**, `Archive Utility` просто **розпакує** його в його поточному місці. Тому, оскільки за замовчуванням папка `LaunchAgents` з `~/Library` не створюється, було можливим **запакувати plist у `LaunchAgents/~$escape.plist`** і **помістити** zip-файл у **`~/Library`**, щоб при розпакуванні він досягнув місця збереження.

Перевірте [**оригінальний звіт тут**](https://objective-see.org/blog/blog\_0x4B.html).

### Word Sandbox bypass via Login Items and .zshenv

(Пам'ятайте, що з першої втечі Word може записувати довільні файли, ім'я яких починається з `~$`).

Однак попередня техніка мала обмеження: якщо папка **`~/Library/LaunchAgents`** існує, тому що інше програмне забезпечення створило її, це призведе до збою. Тому для цього було виявлено інший ланцюг Login Items.

Зловмисник міг створити файли **`.bash_profile`** і **`.zshenv`** з корисним навантаженням для виконання, а потім запакувати їх і **записати zip у папку користувача жертви**: **`~/~$escape.zip`**.

Потім додайте zip-файл до **Login Items** і потім до **додатка Terminal**. Коли користувач повторно входить, zip-файл буде розпакований у файлі користувача, перезаписуючи **`.bash_profile`** і **`.zshenv`**, і, отже, термінал виконає один з цих файлів (в залежності від того, чи використовується bash або zsh).

Перевірте [**оригінальний звіт тут**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Bypass with Open and env variables

З пісочницьких процесів все ще можливо викликати інші процеси, використовуючи утиліту **`open`**. Більше того, ці процеси будуть виконуватися **в межах їх власної пісочниці**.

Було виявлено, що утиліта open має опцію **`--env`** для запуску програми з **конкретними змінними середовища**. Отже, було можливим створити **файл `.zshenv`** у папці **всередині** **пісочниці** і використовувати `open` з `--env`, встановлюючи **змінну `HOME`** на цю папку, відкриваючи додаток `Terminal`, який виконає файл `.zshenv` (з якоїсь причини також було потрібно встановити змінну `__OSINSTALL_ENVIROMENT`).

Перевірте [**оригінальний звіт тут**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Bypass with Open and stdin

Утиліта **`open`** також підтримувала параметр **`--stdin`** (і після попередньої втечі більше не було можливості використовувати `--env`).

Справа в тому, що навіть якщо **`python`** був підписаний Apple, він **не виконає** скрипт з атрибутом **`quarantine`**. Однак було можливим передати йому скрипт з stdin, тому він не перевірить, чи був він під карантином чи ні:&#x20;

1. Скиньте файл **`~$exploit.py`** з довільними командами Python.
2. Запустіть _open_ **`–stdin='~$exploit.py' -a Python`**, що запускає додаток Python з нашим скинутим файлом, що служить його стандартним введенням. Python з радістю виконує наш код, і оскільки це дочірній процес _launchd_, він не підпорядковується правилам пісочниці Word.

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
