# Modélisation des Menaces

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **logiciels malveillants voleurs**.

Le but principal de WhiteIntel est de lutter contre les prises de contrôle de compte et les attaques de ransomware résultant de logiciels malveillants volant des informations.

Vous pouvez consulter leur site Web et essayer leur moteur **gratuitement** sur :

{% embed url="https://whiteintel.io" %}

---

## Modélisation des Menaces

Bienvenue dans le guide complet de HackTricks sur la modélisation des menaces ! Lancez-vous dans une exploration de cet aspect critique de la cybersécurité, où nous identifions, comprenons et élaborons des stratégies contre les vulnérabilités potentielles d'un système. Ce fil conducteur sert de guide étape par étape rempli d'exemples concrets, de logiciels utiles et d'explications faciles à comprendre. Idéal pour les novices et les praticiens expérimentés cherchant à renforcer leurs défenses en cybersécurité.

### Scénarios Couramment Utilisés

1. **Développement de Logiciels** : Dans le cadre du Cycle de Vie de Développement de Logiciels Sécurisé (SSDLC), la modélisation des menaces aide à **identifier les sources potentielles de vulnérabilités** dès les premières étapes du développement.
2. **Tests de Pénétration** : Le cadre d'exécution des tests de pénétration (PTES) exige la **modélisation des menaces pour comprendre les vulnérabilités du système** avant d'effectuer le test.

### Modèle de Menace en Bref

Un Modèle de Menace est généralement représenté sous forme de diagramme, d'image ou d'une autre forme d'illustration visuelle qui dépeint l'architecture planifiée ou existante d'une application. Il ressemble à un **diagramme de flux de données**, mais la principale distinction réside dans sa conception orientée sécurité.

Les modèles de menace comportent souvent des éléments marqués en rouge, symbolisant des vulnérabilités potentielles, des risques ou des barrières. Pour rationaliser le processus d'identification des risques, le triade CIA (Confidentialité, Intégrité, Disponibilité) est utilisé, formant la base de nombreuses méthodologies de modélisation des menaces, STRIDE étant l'une des plus courantes. Cependant, la méthodologie choisie peut varier en fonction du contexte spécifique et des exigences.

### La Triade CIA

La Triade CIA est un modèle largement reconnu dans le domaine de la sécurité de l'information, représentant la Confidentialité, l'Intégrité et la Disponibilité. Ces trois piliers constituent la base sur laquelle de nombreuses mesures de sécurité et politiques sont construites, y compris les méthodologies de modélisation des menaces.

1. **Confidentialité** : Garantir que les données ou le système ne sont pas accessibles par des individus non autorisés. Il s'agit d'un aspect central de la sécurité, nécessitant des contrôles d'accès appropriés, le chiffrement et d'autres mesures pour prévenir les violations de données.
2. **Intégrité** : L'exactitude, la cohérence et la fiabilité des données tout au long de leur cycle de vie. Ce principe garantit que les données ne sont pas altérées ou manipulées par des parties non autorisées. Il implique souvent des sommes de contrôle, des hachages et d'autres méthodes de vérification des données.
3. **Disponibilité** : Cela garantit que les données et les services sont accessibles aux utilisateurs autorisés au moment voulu. Cela implique souvent la redondance, la tolérance aux pannes et des configurations à haute disponibilité pour maintenir les systèmes opérationnels même en cas de perturbations.

### Méthodologies de Modélisation des Menaces

1. **STRIDE** : Développé par Microsoft, STRIDE est un acronyme pour **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service et Elevation of Privilege**. Chaque catégorie représente un type de menace, et cette méthodologie est couramment utilisée dans la phase de conception d'un programme ou d'un système pour identifier les menaces potentielles.
2. **DREAD** : Il s'agit d'une autre méthodologie de Microsoft utilisée pour l'évaluation des risques des menaces identifiées. DREAD signifie **Dommages potentiels, Reproductibilité, Exploitabilité, Utilisateurs affectés et Découvrabilité**. Chacun de ces facteurs est évalué, et le résultat est utilisé pour prioriser les menaces identifiées.
3. **PASTA** (Process for Attack Simulation and Threat Analysis) : Il s'agit d'une méthodologie en sept étapes, centrée sur les risques. Elle comprend la définition et l'identification des objectifs de sécurité, la création d'un périmètre technique, la décomposition de l'application, l'analyse des menaces, l'analyse des vulnérabilités et l'évaluation des risques/triages.
4. **Trike** : Il s'agit d'une méthodologie basée sur les risques qui se concentre sur la défense des actifs. Elle part d'une perspective de **gestion des risques** et examine les menaces et les vulnérabilités dans ce contexte.
5. **VAST** (Visual, Agile, and Simple Threat modeling) : Cette approche vise à être plus accessible et s'intègre dans les environnements de développement Agile. Elle combine des éléments des autres méthodologies et se concentre sur les **représentations visuelles des menaces**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation) : Développé par le CERT Coordination Center, ce cadre est orienté vers l'**évaluation des risques organisationnels plutôt que des systèmes ou des logiciels spécifiques**.

## Outils

Il existe plusieurs outils et solutions logicielles disponibles qui peuvent **aider** à la création et à la gestion des modèles de menace. Voici quelques-uns que vous pourriez envisager.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Une araignée/crawler web GUI avancée multiplateforme et multifonctionnelle pour les professionnels de la cybersécurité. Spider Suite peut être utilisé pour la cartographie et l'analyse de la surface d'attaque.

**Utilisation**

1. Choisissez une URL et Crawl

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualisez le Graphique

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Un projet open-source de l'OWASP, Threat Dragon est à la fois une application web et de bureau qui inclut la création de diagrammes système ainsi qu'un moteur de règles pour générer automatiquement des menaces/mitigations.

**Utilisation**

1. Créez un Nouveau Projet

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Parfois, cela pourrait ressembler à ceci :

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Lancez le Nouveau Projet

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Enregistrez le Nouveau Projet

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Créez votre modèle

Vous pouvez utiliser des outils comme SpiderSuite Crawler pour vous inspirer, un modèle de base ressemblerait à ceci

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Juste un peu d'explication sur les entités :

* Processus (L'entité elle-même telle qu'un serveur web ou une fonctionnalité web)
* Acteur (Une personne telle qu'un visiteur de site web, un utilisateur ou un administrateur)
* Ligne de Flux de Données (Indicateur d'interaction)
* Limite de Confiance (Différents segments réseau ou étendues.)
* Stockage (Endroits où les données sont stockées comme des bases de données)

5. Créez une Menace (Étape 1)

Tout d'abord, vous devez choisir la couche à laquelle vous souhaitez ajouter une menace

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Maintenant, vous pouvez créer la menace

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Gardez à l'esprit qu'il y a une différence entre les Menaces d'Acteurs et les Menaces de Processus. Si vous ajoutez une menace à un Acteur, vous ne pourrez choisir que "Spoofing" et "Repudiation". Cependant, dans notre exemple, nous ajoutons une menace à une entité de Processus, donc nous verrons ceci dans la boîte de création de menace :

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Terminé

Maintenant, votre modèle fini devrait ressembler à ceci. Et voilà comment vous créez un modèle de menace simple avec OWASP Threat Dragon.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Outil de modélisation des menaces Microsoft](https://aka.ms/threatmodelingtool)

Il s'agit d'un outil gratuit de Microsoft qui aide à trouver les menaces dans la phase de conception des projets logiciels. Il utilise la méthodologie STRIDE et est particulièrement adapté à ceux qui développent sur la pile technologique de Microsoft.


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **logiciels malveillants voleurs**.

Leur objectif principal est de lutter contre les prises de contrôle de compte et les attaques de ransomware résultant de logiciels malveillants volant des informations.

Vous pouvez consulter leur site web et essayer leur moteur **gratuitement** sur :

{% embed url="https://whiteintel.io" %}
