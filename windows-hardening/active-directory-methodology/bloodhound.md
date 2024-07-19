# BloodHound & Other AD Enum Tools

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

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) є частиною Sysinternal Suite:

> Розширений переглядач та редактор Active Directory (AD). Ви можете використовувати AD Explorer для легкого навігації в базі даних AD, визначення улюблених місць, перегляду властивостей об'єктів та атрибутів без відкриття діалогових вікон, редагування дозволів, перегляду схеми об'єкта та виконання складних пошуків, які ви можете зберегти та повторно виконати.

### Snapshots

AD Explorer може створювати знімки AD, щоб ви могли перевірити його офлайн.\
Його можна використовувати для виявлення вразливостей офлайн або для порівняння різних станів бази даних AD з часом.

Вам знадобляться ім'я користувача, пароль та напрямок для підключення (необхідний будь-який користувач AD).

Щоб зробити знімок AD, перейдіть до `File` --> `Create Snapshot` і введіть ім'я для знімка.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) є інструментом, який витягує та об'єднує різні артефакти з середовища AD. Інформація може бути представлена у **спеціально відформатованому** звіті Microsoft Excel, який включає підсумкові перегляди з метриками для полегшення аналізу та надання цілісної картини поточного стану цільового середовища AD.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound - це односторінковий веб-додаток на Javascript, побудований на основі [Linkurious](http://linkurio.us/), скомпільований за допомогою [Electron](http://electron.atom.io/), з базою даних [Neo4j](https://neo4j.com/), яка заповнюється збирачем даних на C#.

BloodHound використовує теорію графів, щоб виявити приховані та часто ненавмисні зв'язки в середовищі Active Directory або Azure. Зловмисники можуть використовувати BloodHound, щоб легко ідентифікувати складні шляхи атак, які в іншому випадку було б неможливо швидко виявити. Захисники можуть використовувати BloodHound, щоб ідентифікувати та усунути ті ж самі шляхи атак. Як сині, так і червоні команди можуть використовувати BloodHound, щоб легко отримати глибше розуміння відносин привілеїв в середовищі Active Directory або Azure.

Отже, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) - це чудовий інструмент, який може автоматично перераховувати домен, зберігати всю інформацію, знаходити можливі шляхи ескалації привілеїв і показувати всю інформацію за допомогою графіків.

BloodHound складається з 2 основних частин: **інгесторів** та **додатку візуалізації**.

**Інгестори** використовуються для **перерахунку домену та витягування всієї інформації** в форматі, який зрозуміє додаток візуалізації.

**Додаток візуалізації використовує neo4j** для показу того, як вся інформація пов'язана, і для демонстрації різних способів ескалації привілеїв у домені.

### Installation
Після створення BloodHound CE весь проект був оновлений для зручності використання з Docker. Найпростіший спосіб почати - це використовувати його попередньо налаштовану конфігурацію Docker Compose.

1. Встановіть Docker Compose. Це має бути включено в установку [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Запустіть:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Знайдіть випадково згенерований пароль у виході терміналу Docker Compose.  
4. У браузері перейдіть за адресою http://localhost:8080/ui/login. Увійдіть з ім'ям користувача admin та випадково згенерованим паролем з журналів.  

Після цього вам потрібно буде змінити випадково згенерований пароль, і у вас буде новий інтерфейс, з якого ви зможете безпосередньо завантажити ingestors.  

### SharpHound  

Вони мають кілька варіантів, але якщо ви хочете запустити SharpHound з ПК, приєднаного до домену, використовуючи вашого поточного користувача, і витягти всю інформацію, ви можете зробити:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Ви можете прочитати більше про **CollectionMethod** та сесії циклу [тут](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Якщо ви хочете виконати SharpHound, використовуючи інші облікові дані, ви можете створити сесію CMD netonly і запустити SharpHound звідти:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Дізнайтеся більше про Bloodhound на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) - це інструмент для знаходження **вразливостей** в Active Directory, пов'язаних з **Груповою політикою**. \
Вам потрібно **запустити group3r** з хоста всередині домену, використовуючи **будь-якого доменного користувача**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **оцінює безпекову позицію середовища AD** і надає гарний **звіт** з графіками.

Щоб запустити його, можна виконати бінарний файл `PingCastle.exe`, і він розпочне **інтерактивну сесію**, представляючи меню опцій. За замовчуванням використовується опція **`healthcheck`**, яка встановить базовий **огляд** **домена** та знайде **неправильні налаштування** і **вразливості**.&#x20;

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
