# QaDaj QaD

<details>

<summary><strong>QaDaj AWS hacking vItlhutlhlaH</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks vItlhutlhlaH vItlhutlhlaH:

* QaDaj **company advertised in HackTricks** bejatlhqa' 'ej **HackTricks in PDF** download Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) ghaH 'ej ghaH.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) Discover, [**NFTs**](https://opensea.io/collection/the-peass-family) collection of our exclusive.
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) 'ej [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) 'ej [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### Host header

**Host header** vItlhutlhlaH back-end pagh vItlhutlhlaH vay' **actions**. pIqaD, **domain to send a password reset** vItlhutlhlaH. So, password reset link email vItlhutlhlaH, domain vItlhutlhlaH Host header. vaj, password reset vItlhutlhlaH users 'ej 'ej password reset codes steal vItlhutlhlaH domain controlled by you to one change. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Note that it's possible that you don't even need to wait for the user to click on the reset password link to get the token, as maybe even **spam filters or other intermediary devices/bots will click on it to analyze it**.
{% endhint %}

### Session booleans

Some times when you complete some verification correctly the back-end will **just add a boolean with the value "True" to a security attribute your session**. Then, a different endpoint will know if you successfully passed that check.\
However, if you **pass the check** and your sessions is granted that "True" value in the security attribute, you can try to **access other resources** that **depends on the same attribute** but that you **shouldn't have permissions** to access. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Register functionality

Try to register as an already existent user. Try also using equivalent characters (dots, lots of spaces and Unicode).

### Takeover emails

Register an email, before confirming it change the email, then, if the new confirmation email is sent to the first registered email,you can takeover any email. Or if you can enable the second email confirming the firt one, you can also takeover any account.

### Access Internal servicedesk of companies using atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE method

Developers might forget to disable various debugging options in the production environment. For example, the HTTP `TRACE` method is designed for diagnostic purposes. If enabled, the web server will respond to requests that use the `TRACE` method by echoing in the response the exact request that was received. This behaviour is often harmless, but occasionally leads to information disclosure, such as the name of internal authentication headers that may be appended to requests by reverse proxies.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><strong>QaDaj AWS hacking vItlhutlhlaH</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks vItlhutlhlaH vItlhutlhlaH:

* QaDaj **company advertised in HackTricks** bejatlhqa' 'ej **HackTricks in PDF** download Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) ghaH 'ej ghaH.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) Discover, [**NFTs**](https://opensea.io/collection/the-peass-family) collection of our exclusive.
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) 'ej [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) 'ej [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
