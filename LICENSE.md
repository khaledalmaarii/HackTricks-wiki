{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Licence Creative Commons" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Droit d'auteur © Carlos Polop 2021. Sauf indication contraire (les informations externes copiées dans le livre appartiennent aux auteurs originaux), le texte sur <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> par Carlos Polop est sous licence <a href="https://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)</a>.

Licence : Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)<br>
Licence Lisible par les Humains : https://creativecommons.org/licenses/by-nc/4.0/<br>
Termes Juridiques Complets : https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
Formatage : https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# creative commons

# Attribution-NonCommercial 4.0 International

La Corporation Creative Commons ("Creative Commons") n'est pas un cabinet d'avocats et ne fournit pas de services juridiques ou de conseils juridiques. La distribution des licences publiques de Creative Commons ne crée pas de relation avocat-client ou autre. Creative Commons met ses licences et les informations connexes à disposition "telles quelles". Creative Commons ne donne aucune garantie concernant ses licences, tout matériel sous licence selon leurs termes et conditions, ou toute information connexe. Creative Commons décline toute responsabilité pour les dommages résultant de leur utilisation dans toute la mesure permise.

## Utilisation des Licences Publiques Creative Commons

Les licences publiques Creative Commons fournissent un ensemble standard de termes et conditions que les créateurs et autres titulaires de droits peuvent utiliser pour partager des œuvres originales de création et d'autres matériaux soumis au droit d'auteur et à certains autres droits spécifiés dans la licence publique ci-dessous. Les considérations suivantes sont fournies à titre informatif uniquement, ne sont pas exhaustives et ne font pas partie de nos licences.

* __Considérations pour les concédants de licence :__ Nos licences publiques sont destinées à être utilisées par ceux autorisés à donner au public la permission d'utiliser du matériel de manière autrement restreinte par le droit d'auteur et certains autres droits. Nos licences sont irrévocables. Les concédants de licence doivent lire et comprendre les termes et conditions de la licence qu'ils choisissent avant de l'appliquer. Les concédants de licence doivent également obtenir tous les droits nécessaires avant d'appliquer nos licences afin que le public puisse réutiliser le matériel comme prévu. Les concédants de licence doivent clairement marquer tout matériel qui n'est pas soumis à la licence. Cela inclut d'autres matériaux sous licence CC, ou des matériaux utilisés en vertu d'une exception ou limitation au droit d'auteur. [Plus de considérations pour les concédants de licence](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Considérations pour le public :__ En utilisant l'une de nos licences publiques, un concédant de licence accorde au public la permission d'utiliser le matériel sous licence selon des termes et conditions spécifiés. Si la permission du concédant de licence n'est pas nécessaire pour une raison quelconque - par exemple, en raison de toute exception ou limitation au droit d'auteur applicable - alors cette utilisation n'est pas réglementée par la licence. Nos licences n'accordent que des autorisations en vertu du droit d'auteur et de certains autres droits qu'un concédant de licence est autorisé à accorder. L'utilisation du matériel sous licence peut encore être restreinte pour d'autres raisons, notamment parce que d'autres personnes détiennent des droits d'auteur ou d'autres droits sur le matériel. Un concédant de licence peut formuler des demandes spéciales, telles que demander que tous les changements soient marqués ou décrits. Bien que cela ne soit pas requis par nos licences, vous êtes encouragé à respecter ces demandes dans la mesure du raisonnable. [Plus de considérations pour le public](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Licence Publique Creative Commons Attribution-NonCommercial 4.0 International

En exerçant les Droits Sous Licence (définis ci-dessous), Vous acceptez et consentez à être lié par les termes et conditions de cette Licence Publique Creative Commons Attribution-NonCommercial 4.0 International ("Licence Publique"). Dans la mesure où cette Licence Publique peut être interprétée comme un contrat, Vous bénéficiez des Droits Sous Licence en considération de Votre acceptation de ces termes et conditions, et le Concédant de licence Vous accorde ces droits en considération des avantages que le Concédant de licence reçoit en rendant le Matériel Sous Licence disponible en vertu de ces termes et conditions.

## Section 1 – Définitions.

a. __Matériel Adapté__ signifie du matériel soumis au Droit d'Auteur et aux Droits Similaires qui est dérivé du Matériel Sous Licence et dans lequel le Matériel Sous Licence est traduit, modifié, arrangé, transformé ou autrement modifié d'une manière nécessitant une autorisation en vertu des Droits d'Auteur et des Droits Similaires détenus par le Concédant de licence. Aux fins de cette Licence Publique, lorsque le Matériel Sous Licence est une œuvre musicale, une performance ou un enregistrement sonore, le Matériel Adapté est toujours produit lorsque le Matériel Sous Licence est synchronisé en relation temporelle avec une image en mouvement.

b. __Licence de l'Adaptateur__ signifie la licence que Vous appliquez à Vos Droits d'Auteur et Droits Similaires dans Vos contributions au Matériel Adapté conformément aux termes et conditions de cette Licence Publique.

c. __Droit d'Auteur et Droits Similaires__ signifie le droit d'auteur et/ou des droits similaires étroitement liés au droit d'auteur, y compris, sans s'y limiter, la performance, la diffusion, l'enregistrement sonore et les Droits de Base de Données Sui Generis, sans égard à la manière dont les droits sont étiquetés ou catégorisés. Aux fins de cette Licence Publique, les droits spécifiés à la Section 2(b)(1)-(2) ne sont pas des Droits d'Auteur et Droits Similaires.

d. __Mesures Techniques Efficaces__ signifie les mesures qui, en l'absence d'une autorité appropriée, ne peuvent pas être contournées en vertu des lois remplissant les obligations de l'Article 11 du Traité de l'OMPI sur le droit d'auteur adopté le 20 décembre 1996, et/ou des accords internationaux similaires.

e. __Exceptions et Limitations__ signifie l'utilisation équitable, le traitement équitable et/ou toute autre exception ou limitation aux Droits d'Auteur et Droits Similaires qui s'applique à Votre utilisation du Matériel Sous Licence.

f. __Matériel Sous Licence__ signifie l'œuvre artistique ou littéraire, la base de données ou tout autre matériel auquel le Concédant de licence a appliqué cette Licence Publique.

g. __Droits Sous Licence__ signifie les droits accordés à Vous sous réserve des termes et conditions de cette Licence Publique, qui sont limités à tous les Droits d'Auteur et Droits Similaires qui s'appliquent à Votre utilisation du Matériel Sous Licence et que le Concédant de licence est autorisé à concéder sous licence.

h. __Concédant de licence__ signifie le(s) individu(s) ou l'entité(és) accordant des droits en vertu de cette Licence Publique.

i. __NonCommercial__ signifie non principalement destiné à un avantage commercial ou une compensation monétaire. Aux fins de cette Licence Publique, l'échange du Matériel Sous Licence contre un autre matériel soumis au Droit d'Auteur et aux Droits Similaires par le partage de fichiers numériques ou des moyens similaires est NonCommercial à condition qu'il n'y ait pas de paiement de compensation monétaire en relation avec l'échange.

j. __Partager__ signifie fournir du matériel au public par tout moyen ou processus qui nécessite une autorisation en vertu des Droits Sous Licence, tels que la reproduction, l'affichage public, la représentation publique, la distribution, la diffusion, la communication ou l'importation, et rendre le matériel disponible au public, y compris de manière à ce que les membres du public puissent accéder au matériel à un endroit et à un moment choisis individuellement par eux.

k. __Droits de Base de Données Sui Generis__ signifie des droits autres que le droit d'auteur résultant de la Directive 96/9/CE du Parlement européen et du Conseil du 11 mars 1996 sur la protection juridique des bases de données, telle que modifiée et/ou remplacée, ainsi que d'autres droits essentiellement équivalents partout dans le monde.

l. __Vous__ signifie l'individu ou l'entité exerçant les Droits Sous Licence en vertu de cette Licence Publique. Votre a un sens correspondant.
## Section 2 – Portée.

a. ___Octroi de licence.___

1. Sous réserve des modalités de cette Licence Publique, le Concédant accorde par la présente à Vous une licence mondiale, gratuite, non cessible, non exclusive, irrévocable pour exercer les Droits concédés sur le Matériel sous licence pour :

A. reproduire et Partager le Matériel sous licence, en tout ou en partie, uniquement à des fins non commerciales ; et

B. produire, reproduire et Partager du Matériel Adapté uniquement à des fins non commerciales.

2. __Exceptions et Limitations.__ Pour éviter toute confusion, lorsque des Exceptions et Limitations s'appliquent à Votre utilisation, cette Licence Publique ne s'applique pas, et Vous n'êtes pas tenu de respecter ses modalités.

3. __Durée.__ La durée de cette Licence Publique est spécifiée à la Section 6(a).

4. __Supports et formats ; modifications techniques autorisées.__ Le Concédant Vous autorise à exercer les Droits concédés sur tous les supports et formats, qu'ils soient actuels ou créés ultérieurement, et à apporter les modifications techniques nécessaires pour ce faire. Le Concédant renonce et/ou accepte de ne pas faire valoir un quelconque droit ou autorité pour Vous interdire d'apporter les modifications techniques nécessaires pour exercer les Droits concédés, y compris les modifications techniques nécessaires pour contourner les Mesures Techniques de Protection. Aux fins de cette Licence Publique, le simple fait d'apporter des modifications autorisées par cette Section 2(a)(4) ne produit jamais de Matériel Adapté.

5. __Bénéficiaires ultérieurs.__

A. __Offre du Concédant – Matériel sous licence.__ Chaque bénéficiaire du Matériel sous licence reçoit automatiquement une offre du Concédant pour exercer les Droits concédés aux termes et conditions de cette Licence Publique.

B. __Aucune restriction pour les bénéficiaires ultérieurs.__ Vous ne pouvez pas offrir ou imposer des modalités ou conditions supplémentaires ou différentes, ou appliquer des Mesures Techniques de Protection, sur le Matériel sous licence si cela restreint l'exercice des Droits concédés par tout bénéficiaire du Matériel sous licence.

6. __Absence d'approbation.__ Rien dans cette Licence Publique ne constitue ou ne peut être interprété comme une autorisation pour affirmer ou laisser entendre que Vous êtes, ou que Votre utilisation du Matériel sous licence est, lié à, ou parrainé, approuvé ou doté d'un statut officiel par le Concédant ou d'autres désignés pour recevoir une attribution comme prévu à la Section 3(a)(1)(A)(i).

b. ___Autres droits.___

1. Les droits moraux, tels que le droit à l'intégrité, ne sont pas concédés en vertu de cette Licence Publique, ni la publicité, la vie privée et/ou d'autres droits de personnalité similaires ; cependant, dans la mesure du possible, le Concédant renonce et/ou accepte de ne pas faire valoir de tels droits détenus par le Concédant dans la mesure nécessaire pour Vous permettre d'exercer les Droits concédés, mais pas autrement.

2. Les droits de brevet et de marque ne sont pas concédés en vertu de cette Licence Publique.

3. Dans la mesure du possible, le Concédant renonce à tout droit de percevoir des redevances de Votre part pour l'exercice des Droits concédés, que ce soit directement ou par l'intermédiaire d'une société de gestion dans le cadre de tout régime de licence volontaire ou obligatoire pouvant être renoncé. Dans tous les autres cas, le Concédant se réserve expressément le droit de percevoir de telles redevances, y compris lorsque le Matériel sous licence est utilisé autrement que pour des fins non commerciales.

## Section 3 – Conditions de la licence.

Votre exercice des Droits concédés est expressément soumis aux conditions suivantes.

a. ___Attribution.___

1. Si Vous Partagez le Matériel sous licence (y compris sous forme modifiée), Vous devez :

A. conserver ce qui suit s'il est fourni par le Concédant avec le Matériel sous licence :

i. identification du ou des créateurs du Matériel sous licence et de toute autre personne désignée pour recevoir une attribution, de la manière raisonnablement demandée par le Concédant (y compris sous pseudonyme si désigné) ;

ii. un avis de droit d'auteur ;

iii. un avis faisant référence à cette Licence Publique ;

iv. un avis faisant référence à la clause de non-responsabilité des garanties ;

v. un URI ou un hyperlien vers le Matériel sous licence dans la mesure du raisonnablement possible ;

B. indiquer si Vous avez modifié le Matériel sous licence et conserver une indication de toute modification antérieure ; et

C. indiquer que le Matériel sous licence est concédé sous cette Licence Publique, et inclure le texte de, ou l'URI ou l'hyperlien vers, cette Licence Publique.

2. Vous pouvez satisfaire les conditions de la Section 3(a)(1) de toute manière raisonnable en fonction du support, des moyens et du contexte dans lequel Vous Partagez le Matériel sous licence. Par exemple, il peut être raisonnable de satisfaire les conditions en fournissant un URI ou un hyperlien vers une ressource incluant les informations requises.

3. Si demandé par le Concédant, Vous devez supprimer toute information requise par la Section 3(a)(1)(A) dans la mesure du raisonnablement possible.

4. Si Vous Partagez du Matériel Adapté que Vous produisez, la Licence de l'Adaptateur que Vous appliquez ne doit pas empêcher les destinataires du Matériel Adapté de se conformer à cette Licence Publique.

## Section 4 – Droits de base de données sui generis.

Lorsque les Droits concédés incluent des Droits de base de données sui generis qui s'appliquent à Votre utilisation du Matériel sous licence :

a. pour éviter toute confusion, la Section 2(a)(1) Vous accorde le droit d'extraire, de réutiliser, de reproduire et de Partager tout ou une partie substantielle du contenu de la base de données uniquement à des fins non commerciales ;

b. si Vous incluez tout ou une partie substantielle du contenu de la base de données dans une base de données pour laquelle Vous avez des Droits de base de données sui generis, alors la base de données pour laquelle Vous avez des Droits de base de données sui generis (mais pas son contenu individuel) est un Matériel Adapté ; et

c. Vous devez respecter les conditions de la Section 3(a) si Vous Partagez tout ou une partie substantielle du contenu de la base de données.

Pour éviter toute confusion, cette Section 4 complète et ne remplace pas Vos obligations en vertu de cette Licence Publique lorsque les Droits concédés incluent d'autres Droits d'auteur et Droits similaires.

## Section 5 – Clause de non-responsabilité et limitation de responsabilité.

a. __Sauf disposition contraire expressément prise par le Concédant, dans la mesure du possible, le Concédant offre le Matériel sous licence tel quel et tel que disponible, et ne fait aucune déclaration ou garantie d'aucune sorte concernant le Matériel sous licence, qu'elles soient expresses, implicites, légales ou autres. Cela inclut, sans s'y limiter, les garanties de titre, de qualité marchande, d'adéquation à un usage particulier, d'absence de contrefaçon, d'absence de défauts latents ou autres, d'exactitude, ou de présence ou d'absence d'erreurs, connues ou découvrables. Lorsque les exclusions de garanties ne sont pas autorisées en totalité ou en partie, cette exclusion de responsabilité peut ne pas s'appliquer à Vous.__

b. __Dans la mesure du possible, en aucun cas le Concédant ne pourra être tenu responsable envers Vous sur quelque base légale que ce soit (y compris, sans s'y limiter, la négligence) ou autrement pour tout dommage direct, spécial, indirect, accessoire, consécutif, punitif, exemplaire, ou autres pertes, coûts, dépenses, ou dommages découlant de cette Licence Publique ou de l'utilisation du Matériel sous licence, même si le Concédant a été informé de la possibilité de tels dommages, coûts, dépenses, ou dommages. Lorsqu'une limitation de responsabilité n'est pas autorisée en totalité ou en partie, cette limitation peut ne pas s'appliquer à Vous.__

c. La clause de non-responsabilité et la limitation de responsabilité fournies ci-dessus doivent être interprétées de manière à se rapprocher le plus possible d'une exclusion absolue de responsabilité et d'une renonciation à toute responsabilité.

## Section 6 – Durée et résiliation.

a. Cette Licence Publique s'applique pour la durée des Droits d'auteur et des Droits similaires concédés ici. Cependant, si Vous ne respectez pas cette Licence Publique, alors Vos droits en vertu de cette Licence Publique se terminent automatiquement.

b. Lorsque Votre droit d'utiliser le Matériel sous licence a pris fin en vertu de la Section 6(a), il est rétabli :

1. automatiquement à la date à laquelle la violation est corrigée, à condition qu'elle soit corrigée dans les 30 jours suivant Votre découverte de la violation ; ou

2. sur rétablissement express par le Concédant.

Pour éviter toute confusion, cette Section 6(b) n'affecte pas le droit que le Concédant peut avoir de rechercher des recours pour Vos violations de cette Licence Publique.

c. Pour éviter toute confusion, le Concédant peut également offrir le Matériel sous licence selon des modalités ou conditions séparées ou cesser de distribuer le Matériel sous licence à tout moment ; cependant, cela ne mettra pas fin à cette Licence Publique.

d. Les Sections 1, 5, 6, 7 et 8 survivent à la résiliation de cette Licence Publique.
## Section 7 – Autres conditions.

a. Le concédant ne sera pas lié par des termes ou conditions supplémentaires ou différents communiqués par Vous, sauf accord exprès.

b. Tous arrangements, compréhensions ou accords concernant le Matériel sous licence non mentionnés ici sont distincts et indépendants des termes et conditions de cette Licence Publique.

## Section 8 – Interprétation.

a. Pour éviter toute confusion, cette Licence Publique ne réduit pas, ne limite pas, ne restreint pas ou n'impose pas de conditions à toute utilisation du Matériel sous licence qui pourrait légalement être effectuée sans permission en vertu de cette Licence Publique.

b. Dans la mesure du possible, si une disposition de cette Licence Publique est jugée inapplicable, elle sera automatiquement reformulée dans la mesure minimale nécessaire pour la rendre applicable. Si la disposition ne peut pas être reformulée, elle sera dissociée de cette Licence Publique sans affecter la force exécutoire des termes et conditions restants.

c. Aucun terme ou condition de cette Licence Publique ne sera renoncé et aucun manquement à s'y conformer ne sera consenti sauf accord exprès du concédant.

d. Rien dans cette Licence Publique ne constitue ou ne peut être interprété comme une limitation ou une renonciation à des privilèges et immunités qui s'appliquent au concédant ou à Vous, y compris vis-à-vis des procédures légales de toute juridiction ou autorité.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
