# Аналіз офісних файлів

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) для легкого створення та **автоматизації робочих процесів**, підтримуваних **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

Для отримання додаткової інформації перевірте [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Це лише короткий виклад:

Microsoft створила багато форматів офісних документів, з яких два основні типи - це **OLE формати** (такі як RTF, DOC, XLS, PPT) та **Office Open XML (OOXML) формати** (такі як DOCX, XLSX, PPTX). Ці формати можуть містити макроси, що робить їх цілями для фішингу та шкідливого ПЗ. Файли OOXML структуровані як zip-контейнери, що дозволяє їх перевірку шляхом розпакування, виявляючи ієрархію файлів і папок та вміст XML-файлів.

Щоб дослідити структури файлів OOXML, наведено команду для розпакування документа та структуру виходу. Техніки приховування даних у цих файлах були задокументовані, що вказує на постійні інновації в приховуванні даних у CTF викликах.

Для аналізу **oletools** та **OfficeDissector** пропонують комплексні набори інструментів для вивчення як OLE, так і OOXML документів. Ці інструменти допомагають у виявленні та аналізі вбудованих макросів, які часто слугують векторами для доставки шкідливого ПЗ, зазвичай завантажуючи та виконуючи додаткові шкідливі вантажі. Аналіз VBA макросів можна проводити без Microsoft Office, використовуючи Libre Office, що дозволяє налагоджувати з точками зупинки та змінними спостереження.

Встановлення та використання **oletools** є простими, з командами для встановлення через pip та витягування макросів з документів. Автоматичне виконання макросів викликається такими функціями, як `AutoOpen`, `AutoExec` або `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis), щоб легко створювати та **автоматизувати робочі процеси**, які підтримуються **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
