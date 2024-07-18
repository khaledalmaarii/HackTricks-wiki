{% hint style="success" %}
Impara e pratica l'hacking di AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking di GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}


# Controlla i BSSID

Quando ricevi una cattura il cui traffico principale è Wifi utilizzando WireShark, puoi iniziare a investigare tutti gli SSID della cattura con _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Forza Bruta

Una delle colonne di quella schermata indica se **è stata trovata qualche autenticazione all'interno del pcap**. In tal caso, puoi provare a forzare la password utilizzando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
```markdown
Per esempio recupererà la passphrase WPA che protegge un PSK (pre shared-key), che sarà necessaria per decrittare il traffico successivamente.

# Dati nei Beacon / Canale Laterale

Se sospetti che **i dati stiano fuoriuscendo all'interno dei beacon di una rete Wifi** puoi controllare i beacon della rete utilizzando un filtro come il seguente: `wlan contains <NOMEdellaRETE>`, o `wlan.ssid == "NOMEdellaRETE"` cerca all'interno dei pacchetti filtrati per stringhe sospette.

# Trovare Indirizzi MAC Sconosciuti in una Rete Wifi

Il seguente link sarà utile per trovare le **macchine che inviano dati all'interno di una Rete Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se conosci già gli **indirizzi MAC puoi rimuoverli dall'output** aggiungendo controlli come questo: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una volta individuati gli **indirizzi MAC sconosciuti** che comunicano all'interno della rete puoi utilizzare **filtri** come il seguente: `wlan.addr==<indirizzo MAC> && (ftp || http || ssh || telnet)` per filtrare il suo traffico. Nota che i filtri ftp/http/ssh/telnet sono utili se hai decrittato il traffico.

# Decrittare il Traffico

Modifica --> Preferenze --> Protocolli --> IEEE 802.11--> Modifica

![](<../../../.gitbook/assets/image (426).png>)

```
