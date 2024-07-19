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

Kao **rezime**: ako možete da pišete u **msDS-KeyCredentialLink** svojstvo korisnika/računara, možete da dobijete **NT hash tog objekta**.

U postu je opisana metoda za postavljanje **javnih-privatnih ključeva** za autentifikaciju kako bi se stekao jedinstveni **Service Ticket** koji uključuje NTLM hash cilja. Ovaj proces uključuje enkriptovani NTLM_SUPPLEMENTAL_CREDENTIAL unutar Privilege Attribute Certificate (PAC), koji se može dekriptovati.

### Requirements

Da biste primenili ovu tehniku, određeni uslovi moraju biti ispunjeni:
- Potreban je minimum jedan Windows Server 2016 Domain Controller.
- Domain Controller mora imati instaliran digitalni sertifikat za autentifikaciju servera.
- Active Directory mora biti na Windows Server 2016 funkcionalnom nivou.
- Potreban je nalog sa delegiranim pravima za modifikaciju msDS-KeyCredentialLink atributa ciljnog objekta.

## Abuse

Zloupotreba Key Trust za računar objekata obuhvata korake izvan dobijanja Ticket Granting Ticket (TGT) i NTLM hasha. Opcije uključuju:
1. Kreiranje **RC4 silver ticket** da deluje kao privilegovani korisnici na nameravanom hostu.
2. Korišćenje TGT sa **S4U2Self** za impersonaciju **privilegovanim korisnicima**, što zahteva izmene u Service Ticket-u kako bi se dodala klasa usluge imenu usluge.

Značajna prednost zloupotrebe Key Trust-a je njeno ograničenje na privatni ključ koji generiše napadač, izbegavajući delegaciju potencijalno ranjivim nalozima i ne zahtevajući kreiranje računa računara, što bi moglo biti teško ukloniti.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Zasnovan je na DSInternals koji pruža C# interfejs za ovaj napad. Whisker i njegov Python pandan, **pyWhisker**, omogućavaju manipulaciju `msDS-KeyCredentialLink` atributom kako bi se stekla kontrola nad Active Directory nalozima. Ovi alati podržavaju razne operacije kao što su dodavanje, listanje, uklanjanje i brisanje ključnih kredencijala iz ciljnog objekta.

**Whisker** funkcije uključuju:
- **Add**: Generiše par ključeva i dodaje ključni kredencijal.
- **List**: Prikazuje sve unose ključnih kredencijala.
- **Remove**: Briše određeni ključni kredencijal.
- **Clear**: Briše sve ključne kredencijale, potencijalno ometajući legitimnu upotrebu WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Proširuje funkcionalnost Whisker-a na **UNIX-bazirane sisteme**, koristeći Impacket i PyDSInternals za sveobuhvatne mogućnosti eksploatacije, uključujući listanje, dodavanje i uklanjanje KeyCredentials, kao i uvoz i izvoz u JSON formatu.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray ima za cilj da **iskoristi GenericWrite/GenericAll dozvole koje široke korisničke grupe mogu imati nad domen objektima** kako bi se široko primenili ShadowCredentials. To podrazumeva prijavljivanje na domen, verifikaciju funkcionalnog nivoa domena, enumeraciju domen objekata i pokušaj dodavanja KeyCredentials za sticanje TGT-a i otkrivanje NT hash-a. Opcije čišćenja i rekurzivne taktike eksploatacije povećavaju njegovu korisnost.


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
