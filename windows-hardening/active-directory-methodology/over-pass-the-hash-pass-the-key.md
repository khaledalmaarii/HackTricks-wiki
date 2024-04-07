# Over Pass the Hash/Pass the Key

<details>

<summary><strong>Impara l'hacking AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

L'attacco **Overpass The Hash/Pass The Key (PTK)** è progettato per ambienti in cui il tradizionale protocollo NTLM è limitato e l'autenticazione Kerberos ha la precedenza. Questo attacco sfrutta l'hash NTLM o le chiavi AES di un utente per ottenere i biglietti Kerberos, consentendo l'accesso non autorizzato alle risorse all'interno di una rete.

Per eseguire questo attacco, il primo passo consiste nell'acquisire l'hash NTLM o la password dell'account dell'utente preso di mira. Una volta ottenute queste informazioni, è possibile ottenere un Ticket Granting Ticket (TGT) per l'account, consentendo all'attaccante di accedere a servizi o macchine a cui l'utente ha le autorizzazioni.

Il processo può essere avviato con i seguenti comandi:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Per scenari che richiedono AES256, l'opzione `-aesKey [chiave AES]` può essere utilizzata. Inoltre, il ticket acquisito potrebbe essere utilizzato con vari strumenti, tra cui smbexec.py o wmiexec.py, ampliando così la portata dell'attacco.

Problemi riscontrati come _PyAsn1Error_ o _KDC cannot find the name_ sono tipicamente risolti aggiornando la libreria Impacket o utilizzando il nome host invece dell'indirizzo IP, garantendo la compatibilità con il KDC di Kerberos.

Una sequenza di comandi alternativa utilizzando Rubeus.exe mostra un altro aspetto di questa tecnica:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Questo metodo riflette l'approccio **Pass the Key**, con un focus sul dirottamento e sull'utilizzo diretto del ticket per scopi di autenticazione. È cruciale notare che l'iniziazione di una richiesta TGT attiva l'evento `4768: È stata richiesta un'autenticazione Kerberos (TGT)`, indicando un utilizzo di RC4-HMAC per impostazione predefinita, anche se i sistemi Windows moderni preferiscono AES256.

Per conformarsi alla sicurezza operativa e utilizzare AES256, il seguente comando può essere applicato:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Riferimenti

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
