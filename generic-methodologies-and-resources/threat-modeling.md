# Modélisation des menaces

## Modélisation des menaces

Bienvenue dans le guide complet de HackTricks sur la modélisation des menaces ! Partez à la découverte de cet aspect essentiel de la cybersécurité, où nous identifions, comprenons et élaborons des stratégies contre les vulnérabilités potentielles d'un système. Ce fil de discussion sert de guide étape par étape, regorgeant d'exemples concrets, de logiciels utiles et d'explications faciles à comprendre. Idéal pour les novices et les praticiens expérimentés souhaitant renforcer leurs défenses en matière de cybersécurité.

### Scénarios couramment utilisés

1. **Développement de logiciels** : Dans le cadre du cycle de vie du développement sécurisé des logiciels (SSDLC), la modélisation des menaces aide à **identifier les sources potentielles de vulnérabilités** aux premiers stades de développement.
2. **Tests de pénétration** : Le cadre d'exécution des tests de pénétration (PTES) nécessite la **modélisation des menaces pour comprendre les vulnérabilités du système** avant de procéder au test.

### Modèle de menace en un clin d'œil

Un modèle de menace est généralement représenté sous la forme d'un diagramme, d'une image ou d'une autre forme d'illustration visuelle qui représente l'architecture planifiée ou la construction existante d'une application. Il ressemble à un **diagramme de flux de données**, mais la distinction clé réside dans sa conception axée sur la sécurité.

Les modèles de menace comportent souvent des éléments marqués en rouge, symbolisant les vulnérabilités potentielles, les risques ou les obstacles. Pour rationaliser le processus d'identification des risques, le triptyque CIA (Confidentialité, Intégrité, Disponibilité) est utilisé, formant la base de nombreuses méthodologies de modélisation des menaces, STRIDE étant l'une des plus courantes. Cependant, la méthodologie choisie peut varier en fonction du contexte spécifique et des exigences.

### Le triptyque CIA

Le triptyque CIA est un modèle largement reconnu dans le domaine de la sécurité de l'information, qui signifie Confidentialité, Intégrité et Disponibilité. Ces trois piliers constituent la base sur laquelle de nombreuses mesures de sécurité et politiques sont construites, y compris les méthodologies de modélisation des menaces.

1. **Confidentialité** : Garantir que les données ou le système ne sont pas accessibles par des personnes non autorisées. Il s'agit d'un aspect central de la sécurité, nécessitant des contrôles d'accès appropriés, le chiffrement et d'autres mesures pour prévenir les violations de données.
2. **Intégrité** : L'exactitude, la cohérence et la fiabilité des données tout au long de leur cycle de vie. Ce principe garantit que les données ne sont pas modifiées ou altérées par des parties non autorisées. Il implique souvent des sommes de contrôle, des fonctions de hachage et d'autres méthodes de vérification des données.
3. **Disponibilité** : Cela garantit que les données et les services sont accessibles aux utilisateurs autorisés lorsque cela est nécessaire. Cela implique souvent la redondance, la tolérance aux pannes et des configurations haute disponibilité pour maintenir les systèmes en fonctionnement même en cas de perturbations.

### Méthodologies de modélisation des menaces

1. **STRIDE** : Développée par Microsoft, STRIDE est un acronyme pour **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service et Elevation of Privilege**. Chaque catégorie représente un type de menace, et cette méthodologie est couramment utilisée dans la phase de conception d'un programme ou d'un système pour identifier les menaces potentielles.
2. **DREAD** : Il s'agit d'une autre méthodologie de Microsoft utilisée pour l'évaluation des risques liés aux menaces identifiées. DREAD signifie **Damage potential, Reproducibility, Exploitability, Affected users et Discoverability**. Chacun de ces facteurs est évalué et le résultat est utilisé pour hiérarchiser les menaces identifiées.
3. **PASTA** (Process for Attack Simulation and Threat Analysis) : Il s'agit d'une méthodologie en sept étapes, **centrée sur les risques**. Elle comprend la définition et l'identification des objectifs de sécurité, la création d'une portée technique, la décomposition de l'application, l'analyse des menaces, l'analyse des vulnérabilités et l'évaluation des risques/triages.
4. **Trike** : Il s'agit d'une méthodologie basée sur les risques qui se concentre sur la défense des actifs. Elle part d'une perspective de **gestion des risques** et examine les menaces et les vulnérabilités dans ce contexte.
5. **VAST** (Visual, Agile et Simple Threat modeling) : Cette approche vise à être plus accessible et s'intègre dans les environnements de développement Agile. Elle combine des éléments des autres méthodologies et met l'accent sur les **représentations visuelles des menaces**.
6. **OCTAVE** (Operationally Critical Threat, Asset et Vulnerability Evaluation) : Développé par le CERT Coordination Center, ce cadre est axé sur **l'évaluation des risques organisationnels plutôt que sur des systèmes ou des logiciels spécifiques**.

## Outils

Il existe plusieurs outils et solutions logicielles disponibles qui peuvent **aider** à la création et à la gestion des modèles de menaces. Voici quelques-uns que vous pourriez envisager.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Une suite avancée de spider/crawler GUI multiplateforme pour les professionnels de la cybersécurité. Spider Suite peut être utilisé pour la cartographie et l'analyse de la surface d'attaque.

**Utilisation**

1. Choisissez une URL et effectuez une exploration

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Affichez le graphique

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Un projet open source d'OWASP, Threat Dragon est à la fois une application web et de bureau qui comprend la création de diagrammes système ainsi qu'un moteur de règles pour générer automatiquement des menaces/mitigations.

**Utilisation**

1. Créez un nouveau projet

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Parfois, cela peut ressembler à ceci :

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Lancez le nouveau projet

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Enregistrez le nouveau projet

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Créez votre modèle

Vous pouvez utiliser des outils tels que SpiderSuite Crawler pour vous inspirer, un modèle de base ressemblerait à ceci

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Juste un peu d'explication sur les entités :

* Processus (L'entité elle-même, telle qu'un serveur web ou une fonctionnalité web)
* Acteur (Une personne, telle qu'un visiteur de site web, un utilisateur ou un administrateur)
* Ligne de flux de données (Indicateur d'interaction)
* Limite de confiance (Différents segments de réseau ou domaines.)
* Stockage (Endroits où les données sont stockées, tels que les bases de données)

5. Créez une menace (Étape 1)

D'abord, vous devez choisir la couche à laquelle vous souhaitez ajouter une menace

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Maintenant, vous pouvez créer la menace

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Gardez à l'esprit qu'il y a une différence entre les menaces d'acteurs et les menaces de processus. Si vous ajoutez une menace à un acteur, vous ne pourrez choisir que "Spoofing" et "Repudiation". Cependant, dans notre exemple, nous ajoutons une menace à une entité de processus, nous verrons donc ceci dans la boîte de création de menace :

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Terminé

Maintenant, votre modèle terminé devrait ressembler à ceci. Et voilà comment vous créez un modèle de menace simple avec OWASP Threat Dragon.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Outil de modélisation des menaces de Microsoft](https://aka.ms/threatmodelingtool)

C'est un outil gratuit de Microsoft qui aide à trouver les menaces dans la phase de conception des projets logiciels. Il utilise la méthodologie STRIDE et est particulièrement adapté à ceux qui développent sur la pile technologique de Microsoft.
