# Shadow Credentials

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

## Intro <a href="#3f17" id="3f17"></a>

**Check the original post for [all the information about this technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

As **summary**: if you can write to the **msDS-KeyCredentialLink** property of a user/computer, you can retrieve the **NT hash of that object**.

In the post, a method is outlined for setting up **public-private key authentication credentials** to acquire a unique **Service Ticket** that includes the target's NTLM hash. This process involves the encrypted NTLM_SUPPLEMENTAL_CREDENTIAL within the Privilege Attribute Certificate (PAC), which can be decrypted.

### Requirements

To apply this technique, certain conditions must be met:
- A minimum of one Windows Server 2016 Domain Controller is needed.
- The Domain Controller must have a server authentication digital certificate installed.
- The Active Directory must be at the Windows Server 2016 Functional Level.
- An account with delegated rights to modify the msDS-KeyCredentialLink attribute of the target object is required.

## Abuse

The abuse of Key Trust for computer objects encompasses steps beyond obtaining a Ticket Granting Ticket (TGT) and the NTLM hash. The options include:
1. Creating an **RC4 silver ticket** to act as privileged users on the intended host.
2. Using the TGT with **S4U2Self** for impersonation of **privileged users**, necessitating alterations to the Service Ticket to add a service class to the service name.

A significant advantage of Key Trust abuse is its limitation to the attacker-generated private key, avoiding delegation to potentially vulnerable accounts and not requiring the creation of a computer account, which could be challenging to remove.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

It's based on DSInternals providing a C# interface for this attack. Whisker and its Python counterpart, **pyWhisker**, enable manipulation of the `msDS-KeyCredentialLink` attribute to gain control over Active Directory accounts. These tools support various operations like adding, listing, removing, and clearing key credentials from the target object.

**Whisker** functions include:
- **Add**: Generates a key pair and adds a key credential.
- **List**: Displays all key credential entries.
- **Remove**: Deletes a specified key credential.
- **Clear**: Erases all key credentials, potentially disrupting legitimate WHfB usage.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Rozszerza funkcjonalność Whisker do **systemów opartych na UNIX**, wykorzystując Impacket i PyDSInternals do kompleksowych możliwości eksploatacji, w tym listowania, dodawania i usuwania KeyCredentials, a także importowania i eksportowania ich w formacie JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray ma na celu **wykorzystanie uprawnień GenericWrite/GenericAll, które szerokie grupy użytkowników mogą mieć nad obiektami domeny**, aby szeroko stosować ShadowCredentials. Obejmuje to logowanie się do domeny, weryfikację poziomu funkcjonalnego domeny, enumerację obiektów domeny oraz próbę dodania KeyCredentials w celu uzyskania TGT i ujawnienia NT hash. Opcje czyszczenia i taktyki rekurencyjnego wykorzystywania zwiększają jego użyteczność.


## References

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

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
