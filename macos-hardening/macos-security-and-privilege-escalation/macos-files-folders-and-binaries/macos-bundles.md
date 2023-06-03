## Informations de base

Fondamentalement, un bundle est une **structure de répertoire** dans le système de fichiers. De manière intéressante, par défaut, ce répertoire **ressemble à un seul objet dans Finder**. 

Le bundle **le plus courant** que nous rencontrerons est le **bundle `.app`**, mais de nombreux autres exécutables sont également empaquetés sous forme de bundles, tels que **`.framework`** et **`.systemextension`** ou **`.kext`**.

Les types de ressources contenues dans un bundle peuvent consister en des applications, des bibliothèques, des images, de la documentation, des fichiers d'en-tête, etc. Tous ces fichiers se trouvent dans `<application>.app/Contents/`.
```bash
ls -lR /Applications/Safari.app/Contents
```
*   `Contents/_CodeSignature`

    Contient des informations de **signature de code** sur l'application (c'est-à-dire des hachages, etc.).
*   `Contents/MacOS`

    Contient le **binaire de l'application** (qui est exécuté lorsque l'utilisateur double-clique sur l'icône de l'application dans l'interface utilisateur).
*   `Contents/Resources`

    Contient les **éléments d'interface utilisateur de l'application**, tels que des images, des documents et des fichiers nib/xib (qui décrivent diverses interfaces utilisateur).
* `Contents/Info.plist`\
  Le **fichier de configuration principal** de l'application. Apple note que "le système compte sur la présence de ce fichier pour identifier les informations pertinentes sur l'application et les fichiers associés".
  * Les **fichiers Plist** contiennent des informations de configuration. Vous pouvez trouver des informations sur la signification des clés plist sur [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
  *   Les paires qui peuvent être intéressantes lors de l'analyse d'une application comprennent:\\

      * **CFBundleExecutable**

      Contient le **nom du binaire de l'application** (trouvé dans Contents/MacOS).

      * **CFBundleIdentifier**

      Contient l'identifiant de bundle de l'application (souvent utilisé par le système pour **identifier** globalement l'application).

      * **LSMinimumSystemVersion**

      Contient la **plus ancienne version** de **macOS** avec laquelle l'application est compatible.
