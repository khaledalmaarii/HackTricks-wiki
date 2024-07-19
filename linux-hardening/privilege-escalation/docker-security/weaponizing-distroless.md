# Weaponizing Distroless

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

## Τι είναι το Distroless

Ένα distroless container είναι ένας τύπος container που **περιέχει μόνο τις απαραίτητες εξαρτήσεις για να τρέξει μια συγκεκριμένη εφαρμογή**, χωρίς επιπλέον λογισμικό ή εργαλεία που δεν απαιτούνται. Αυτά τα containers έχουν σχεδιαστεί για να είναι όσο το δυνατόν **ελαφρύτερα** και **ασφαλέστερα**, και στοχεύουν να **ελαχιστοποιήσουν την επιφάνεια επίθεσης** αφαιρώντας οποιαδήποτε περιττά στοιχεία.

Τα distroless containers χρησιμοποιούνται συχνά σε **παραγωγικά περιβάλλοντα όπου η ασφάλεια και η αξιοπιστία είναι πρωταρχικής σημασίας**.

Ορισμένα **παραδείγματα** **distroless containers** είναι:

* Παρέχονται από **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Παρέχονται από **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Ο στόχος της οπλοποίησης ενός distroless container είναι να μπορεί να **εκτελεί αυθαίρετους δυαδικούς κώδικες και payloads ακόμη και με τους περιορισμούς** που επιβάλλει το **distroless** (έλλειψη κοινών δυαδικών κωδικών στο σύστημα) και επίσης προστασίες που συχνά βρίσκονται σε containers όπως **μόνο για ανάγνωση** ή **χωρίς εκτέλεση** στο `/dev/shm`.

### Μέσω μνήμης

Έρχεται κάποια στιγμή το 2023...

### Μέσω Υπαρχόντων δυαδικών κωδικών

#### openssl

****[**Σε αυτή την ανάρτηση,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) εξηγείται ότι ο δυαδικός κώδικας **`openssl`** βρίσκεται συχνά σε αυτά τα containers, πιθανώς επειδή είναι **απαραίτητος** από το λογισμικό που πρόκειται να εκτελείται μέσα στο container.
{% hnt stye="acceas" %}
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
