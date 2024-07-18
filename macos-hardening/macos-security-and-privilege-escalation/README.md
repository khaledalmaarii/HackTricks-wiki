# Безпека та підвищення привілеїв в macOS

{% hint style="success" %}
Вивчайте та практикуйте хакінг AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання AWS Red Team Expert (ARTE) від HackTricks**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання GCP Red Team Expert (GRTE) від HackTricks**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакінг-прийоми, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **та** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub.**

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими хакерами та мисливцями за вразливостями!

**Інсайти щодо хакінгу**\
Вивчайте контент, який досліджує захоплення та виклики хакінгу

**Новини про хакінг у реальному часі**\
Будьте в курсі швидкозмінного світу хакінгу завдяки новинам та інсайтам у реальному часі

**Останні оголошення**\
Будьте в курсі нових програм винагород за вразливості та важливих оновлень платформи

**Приєднуйтесь до нас на** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **і почніть співпрацювати з найкращими хакерами вже сьогодні!**

## Основи MacOS

Якщо ви не знайомі з macOS, вам слід почати з основ:

* Спеціальні файли та дозволи в macOS:

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Загальні користувачі macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* Архітектура ядра

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Загальні мережеві служби та протоколи macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Для завантаження `tar.gz` змініть URL, наприклад, з [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) на [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

У компаніях системи macOS ймовірно будуть **керуватися за допомогою MDM**. Тому з погляду атакувальника цікаво знати **як це працює**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Інспектування, Налагодження та Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Захист в MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Поверхня атаки

### Дозволи на файли

Якщо **процес, який працює в якості root, записує** файл, яким може керувати користувач, користувач може скористатися цим для **підвищення привілеїв**.\
Це може статися у таких ситуаціях:

* Файл вже був створений користувачем (належить користувачеві)
* Файл може бути записаний користувачем через групу
* Файл знаходиться всередині каталогу, який належить користувачеві (користувач може створити файл)
* Файл знаходиться всередині каталогу, який належить root, але користувач має права на запис через групу (користувач може створити файл)

Можливість **створення файлу**, який буде **використовуватися root**, дозволяє користувачеві **використовувати його вміст** або навіть створювати **символічні посилання/жорсткі посилання**, щоб вказати його в інше місце.

Для цього типу вразливостей не забувайте **перевіряти вразливі встановлювачі `.pkg`**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Розширення файлів та обробники URL-схем додатків

Дивні додатки, зареєстровані за допомогою розширень файлів, можуть бути використані для зловживання, і різні додатки можуть бути зареєстровані для відкриття конкретних протоколів

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Підвищення привілеїв TCC / SIP в macOS

У macOS **додатки та бінарні файли можуть мати дозволи** на доступ до папок або налаштувань, що робить їх більш привілейованими, ніж інші.

Отже, атакувальник, який хоче успішно скомпрометувати машину macOS, повинен **підвищити свої привілеї TCC** (або навіть **обійти SIP**, залежно від своїх потреб).

Ці привілеї зазвичай надаються у формі **привілеїв**, з якими додаток підписаний, або додаток може запитати деякі доступи, і після **затвердження користувачем** вони можуть бути знайдені в **базах даних TCC**. Інший спосіб, яким процес може отримати ці привілеї, - це бути **дитиною процесу** з цими **привілеями**, оскільки вони зазвичай **успадковуються**.

Перейдіть за цими посиланнями, щоб знайти різні способи [**підвищення привілеїв в TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**обхід TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) та як у минулому [**було обійдено SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Традиційне підвищення привілеїв в macOS

Звісно, з погляду червоних команд вам також слід зацікавитися підвищенням до root. Перевірте наступний пост для деяких підказок:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Посилання

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими хакерами та мисливцями за багами!

**Інсайти щодо Хакінгу**\
Взаємодійте з контентом, який досліджує захоплення та виклики хакінгу

**Новини про Хакінг у Реальному Часі**\
Будьте в курсі швидкозмінного світу хакінгу завдяки новинам та інсайтам у реальному часі

**Останні Оголошення**\
Будьте в курсі найновіших запусків баг баунті та важливих оновлень платформи

Приєднуйтесь до нас на [**Discord**](https://discord.com/invite/N3FrSbmwdy) та почніть співпрацювати з найкращими хакерами вже сьогодні!

{% hint style="success" %}
Вивчайте та практикуйте Хакінг AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте Хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
