# macOS Dirty NIB

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

**Для отримання додаткової інформації про техніку перегляньте оригінальний пост за адресою:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) та наступний пост від [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Ось короткий виклад:

### Що таке Nib файли

Nib (скорочення від NeXT Interface Builder) файли, частина екосистеми розробки Apple, призначені для визначення **UI елементів** та їх взаємодій в додатках. Вони містять серіалізовані об'єкти, такі як вікна та кнопки, і завантажуються під час виконання. Незважаючи на їхнє постійне використання, Apple тепер рекомендує Storyboards для більш комплексної візуалізації потоку UI.

Основний Nib файл згадується в значенні **`NSMainNibFile`** всередині файлу `Info.plist` додатку і завантажується функцією **`NSApplicationMain`**, яка виконується в функції `main` додатку.

### Процес ін'єкції Dirty Nib

#### Створення та налаштування NIB файлу

1. **Початкове налаштування**:
* Створіть новий NIB файл за допомогою XCode.
* Додайте об'єкт до інтерфейсу, встановивши його клас на `NSAppleScript`.
* Налаштуйте початкову властивість `source` через атрибути часу виконання, визначені користувачем.
2. **Гаджет виконання коду**:
* Налаштування дозволяє виконувати AppleScript за запитом.
* Інтегруйте кнопку для активації об'єкта `Apple Script`, спеціально викликаючи селектор `executeAndReturnError:`.
3. **Тестування**:
*   Простий Apple Script для тестування:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```
* Тестуйте, запустивши в налагоджувачі XCode та натиснувши кнопку.

#### Цілеве застосування (приклад: Pages)

1. **Підготовка**:
* Скопіюйте цільовий додаток (наприклад, Pages) в окрему директорію (наприклад, `/tmp/`).
* Запустіть додаток, щоб обійти проблеми з Gatekeeper і кешувати його.
2. **Перезапис NIB файлу**:
* Замініть існуючий NIB файл (наприклад, NIB панелі "Про програму") на створений DirtyNIB файл.
3. **Виконання**:
* Запустіть виконання, взаємодіючи з додатком (наприклад, вибравши пункт меню `About`).

#### Доказ концепції: доступ до даних користувача

* Змініть AppleScript, щоб отримати доступ і витягти дані користувача, такі як фотографії, без згоди користувача.

### Приклад коду: Зловмисний .xib файл

* Отримайте доступ і перегляньте [**зразок зловмисного .xib файлу**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4), який демонструє виконання довільного коду.

### Інший приклад

У пості [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) ви можете знайти навчальний посібник про те, як створити dirty nib.&#x20;

### Вирішення обмежень запуску

* Обмеження запуску заважають виконанню додатків з несподіваних місць (наприклад, `/tmp`).
* Можливо виявити додатки, які не захищені обмеженнями запуску, і націлити їх для ін'єкції NIB файлів.

### Додаткові захисти macOS

З macOS Sonoma і далі, модифікації всередині пакетів додатків обмежені. Однак раніше методи включали:

1. Копіювання додатку в інше місце (наприклад, `/tmp/`).
2. Перейменування директорій всередині пакету додатку, щоб обійти початкові захисти.
3. Після запуску додатку для реєстрації з Gatekeeper, модифікація пакету додатку (наприклад, заміна MainMenu.nib на Dirty.nib).
4. Повернення директорій назад і повторний запуск додатку для виконання ін'єкованого NIB файлу.

**Примітка**: Останні оновлення macOS зменшили ефективність цього експлойту, заборонивши модифікацію файлів у пакетах додатків після кешування Gatekeeper, що робить експлойт неефективним.

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
