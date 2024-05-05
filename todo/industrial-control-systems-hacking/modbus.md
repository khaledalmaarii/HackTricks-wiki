# Le Protocole Modbus

## Introduction au Protocole Modbus

Le protocole Modbus est un protocole largement utilisé dans l'Automatisation Industrielle et les Systèmes de Contrôle. Modbus permet la communication entre divers appareils tels que les automates programmables (PLC), les capteurs, les actionneurs et autres dispositifs industriels. Comprendre le Protocole Modbus est essentiel car il s'agit du protocole de communication le plus utilisé dans les ICS et présente une grande surface d'attaque potentielle pour l'écoute et même l'injection de commandes dans les PLC.

Ici, les concepts sont énoncés point par point en fournissant le contexte du protocole et sa nature de fonctionnement. Le plus grand défi en matière de sécurité des systèmes ICS est le coût de mise en œuvre et de mise à niveau. Ces protocoles et normes ont été conçus dans les années 80 et 90 et sont toujours largement utilisés. Comme une industrie comporte de nombreux appareils et connexions, la mise à niveau des appareils est très difficile, ce qui donne aux hackers un avantage pour traiter avec des protocoles obsolètes. Les attaques sur Modbus sont pratiquement inévitables car il est utilisé sans mise à niveau et son fonctionnement est critique pour l'industrie.

## L'Architecture Client-Serveur

Le Protocole Modbus est généralement utilisé dans une architecture Client-Serveur où un appareil maître (client) initie la communication avec un ou plusieurs appareils esclaves (serveurs). Cela est également appelé architecture Maître-Esclave, largement utilisée dans l'électronique et l'IoT avec SPI, I2C, etc.

## Versions Série et Ethernet

Le Protocole Modbus est conçu pour la Communication Série ainsi que pour les Communications Ethernet. La Communication Série est largement utilisée dans les systèmes hérités tandis que les appareils modernes prennent en charge l'Ethernet qui offre des débits élevés et est plus adapté aux réseaux industriels modernes.

## Représentation des Données

Les données sont transmises dans le protocole Modbus en ASCII ou en binaire, bien que le format binaire soit utilisé en raison de sa compatibilité avec les anciens appareils.

## Codes de Fonction

Le Protocole Modbus fonctionne avec la transmission de codes de fonction spécifiques qui sont utilisés pour faire fonctionner les PLC et divers dispositifs de contrôle. Cette partie est importante à comprendre car des attaques de rejeu peuvent être effectuées en retransmettant des codes de fonction. Les appareils hérités ne prennent pas en charge le cryptage des données en transmission et ont généralement de longs câbles qui les connectent, ce qui entraîne la manipulation de ces câbles et la capture/l'injection de données.

## Adressage de Modbus

Chaque appareil dans le réseau a une adresse unique qui est essentielle pour la communication entre les appareils. Des protocoles comme Modbus RTU, Modbus TCP, etc. sont utilisés pour implémenter l'adressage et servent de couche de transport pour la transmission des données. Les données transférées sont au format du protocole Modbus qui contient le message.

De plus, Modbus implémente également des vérifications d'erreur pour assurer l'intégrité des données transmises. Mais surtout, Modbus est une Norme Ouverte et n'importe qui peut l'implémenter dans ses appareils. Cela a permis à ce protocole de devenir une norme mondiale et il est largement utilisé dans l'industrie de l'automatisation industrielle.

En raison de son utilisation à grande échelle et du manque de mises à niveau, attaquer Modbus offre un avantage significatif avec sa surface d'attaque. Les ICS dépendent fortement de la communication entre les appareils et toute attaque contre eux peut être dangereuse pour le fonctionnement des systèmes industriels. Des attaques telles que le rejeu, l'injection de données, l'écoute et la fuite de données, le déni de service, la falsification de données, etc. peuvent être effectuées si le moyen de transmission est identifié par l'attaquant.
