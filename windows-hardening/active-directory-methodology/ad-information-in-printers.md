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


Є кілька блогів в Інтернеті, які **підкреслюють небезпеки залишення принтерів, налаштованих з LDAP з за замовчуванням/слабкими** обліковими даними для входу.\
Це пов'язано з тим, що зловмисник може **змусити принтер аутентифікуватися на підробленому LDAP сервері** (зазвичай `nc -vv -l -p 444` достатньо) і захопити **облікові дані принтера у відкритому тексті**.

Крім того, кілька принтерів міститимуть **журнали з іменами користувачів** або навіть можуть **завантажити всі імена користувачів** з контролера домену.

Вся ця **чутлива інформація** та загальна **відсутність безпеки** роблять принтери дуже цікавими для зловмисників.

Деякі блоги на цю тему:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Налаштування принтера
- **Місцезнаходження**: Список LDAP серверів знаходиться за адресою: `Network > LDAP Setting > Setting Up LDAP`.
- **Поведение**: Інтерфейс дозволяє змінювати LDAP сервери без повторного введення облікових даних, що спрямовано на зручність користувача, але створює ризики безпеки.
- **Експлуатація**: Експлуатація полягає в перенаправленні адреси LDAP сервера на контрольовану машину та використанні функції "Перевірити з'єднання" для захоплення облікових даних.

## Захоплення облікових даних

**Для більш детальних кроків зверніться до оригінального [джерела](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Метод 1: Слухач Netcat
Простий слухач netcat може бути достатнім:
```bash
sudo nc -k -v -l -p 386
```
Однак успіх цього методу варіюється.

### Метод 2: Повний LDAP сервер з Slapd
Більш надійний підхід передбачає налаштування повного LDAP сервера, оскільки принтер виконує нульове з'єднання, а потім запит перед спробою прив'язки облікових даних.

1. **Налаштування LDAP сервера**: Посібник слідує крокам з [цього джерела](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Ключові кроки**:
- Встановіть OpenLDAP.
- Налаштуйте пароль адміністратора.
- Імпортуйте базові схеми.
- Встановіть доменне ім'я на LDAP БД.
- Налаштуйте LDAP TLS.
3. **Виконання служби LDAP**: Після налаштування службу LDAP можна запустити за допомогою:
```bash
slapd -d 2
```
## Посилання
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
