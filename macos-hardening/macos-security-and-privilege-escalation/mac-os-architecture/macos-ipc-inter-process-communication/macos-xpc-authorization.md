## Autorisation XPC

Apple propose également une autre façon d'authentifier si le processus de connexion a les **permissions pour appeler une méthode XPC exposée**.

Lorsqu'une application a besoin d'**exécuter des actions en tant qu'utilisateur privilégié**, au lieu d'exécuter l'application en tant qu'utilisateur privilégié, elle installe généralement en tant que root un HelperTool en tant que service XPC qui peut être appelé depuis l'application pour effectuer ces actions. Cependant, l'application appelant le service doit avoir suffisamment d'autorisations.

### ShuoldAcceptNewConnection toujours YES

Un exemple peut être trouvé dans [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Dans `App/AppDelegate.m`, il essaie de **se connecter** au **HelperTool**. Et dans `HelperTool/HelperTool.m`, la fonction **`shouldAcceptNewConnection`** **ne vérifiera pas** les exigences indiquées précédemment. Elle renverra toujours YES:
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
    // Called by our XPC listener when a new connection comes in.  We configure the connection
    // with our protocol and ourselves as the main object.
{
    assert(listener == self.listener);
    #pragma unused(listener)
    assert(newConnection != nil);

    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(HelperToolProtocol)];
    newConnection.exportedObject = self;
    [newConnection resume];
    
    return YES;
}
```
Pour plus d'informations sur la façon de configurer correctement cette vérification :

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

### Droits d'application

Cependant, il y a une certaine **autorisation en cours lorsqu'une méthode du HelperTool est appelée**.

La fonction **`applicationDidFinishLaunching`** de `App/AppDelegate.m` créera une référence d'autorisation vide après le démarrage de l'application. Cela devrait toujours fonctionner.\
Ensuite, il essaiera d'**ajouter certains droits** à cette référence d'autorisation en appelant `setupAuthorizationRights`:
```objectivec
- (void)applicationDidFinishLaunching:(NSNotification *)note
{
    [...]
    err = AuthorizationCreate(NULL, NULL, 0, &self->_authRef);
    if (err == errAuthorizationSuccess) {
        err = AuthorizationMakeExternalForm(self->_authRef, &extForm);
    }
    if (err == errAuthorizationSuccess) {
        self.authorization = [[NSData alloc] initWithBytes:&extForm length:sizeof(extForm)];
    }
    assert(err == errAuthorizationSuccess);
    
    // If we successfully connected to Authorization Services, add definitions for our default 
    // rights (unless they're already in the database).
    
    if (self->_authRef) {
        [Common setupAuthorizationRights:self->_authRef];
    }
    
    [self.window makeKeyAndOrderFront:self];
}
```
La fonction `setupAuthorizationRights` de `Common/Common.m` stockera dans la base de données d'autorisation `/var/db/auth.db` les droits de l'application. Notez comment elle n'ajoutera que les droits qui ne sont pas encore dans la base de données :
```objectivec
+ (void)setupAuthorizationRights:(AuthorizationRef)authRef
    // See comment in header.
{
    assert(authRef != NULL);
    [Common enumerateRightsUsingBlock:^(NSString * authRightName, id authRightDefault, NSString * authRightDesc) {
        OSStatus    blockErr;
        
        // First get the right.  If we get back errAuthorizationDenied that means there's 
        // no current definition, so we add our default one.
        
        blockErr = AuthorizationRightGet([authRightName UTF8String], NULL);
        if (blockErr == errAuthorizationDenied) {
            blockErr = AuthorizationRightSet(
                authRef,                                    // authRef
                [authRightName UTF8String],                 // rightName
                (__bridge CFTypeRef) authRightDefault,      // rightDefinition
                (__bridge CFStringRef) authRightDesc,       // descriptionKey
                NULL,                                       // bundle (NULL implies main bundle)
                CFSTR("Common")                             // localeTableName
            );
            assert(blockErr == errAuthorizationSuccess);
        } else { 
            // A right already exists (err == noErr) or any other error occurs, we 
            // assume that it has been set up in advance by the system administrator or
            // this is the second time we've run.  Either way, there's nothing more for 
            // us to do.
        }
    }];
}
```
La fonction `enumerateRightsUsingBlock` est celle utilisée pour obtenir les autorisations des applications, qui sont définies dans `commandInfo`:
```objectivec
static NSString * kCommandKeyAuthRightName    = @"authRightName";
static NSString * kCommandKeyAuthRightDefault = @"authRightDefault";
static NSString * kCommandKeyAuthRightDesc    = @"authRightDescription";

+ (NSDictionary *)commandInfo
{
    static dispatch_once_t sOnceToken;
    static NSDictionary *  sCommandInfo;
    
    dispatch_once(&sOnceToken, ^{
        sCommandInfo = @{
            NSStringFromSelector(@selector(readLicenseKeyAuthorization:withReply:)) : @{
                kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.readLicenseKey", 
                kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow, 
                kCommandKeyAuthRightDesc    : NSLocalizedString(
                    @"EBAS is trying to read its license key.", 
                    @"prompt shown when user is required to authorize to read the license key"
                )
            },
            NSStringFromSelector(@selector(writeLicenseKey:authorization:withReply:)) : @{
                kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.writeLicenseKey", 
                kCommandKeyAuthRightDefault : @kAuthorizationRuleAuthenticateAsAdmin, 
                kCommandKeyAuthRightDesc    : NSLocalizedString(
                    @"EBAS is trying to write its license key.", 
                    @"prompt shown when user is required to authorize to write the license key"
                )
            },
            NSStringFromSelector(@selector(bindToLowNumberPortAuthorization:withReply:)) : @{
                kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.startWebService", 
                kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow, 
                kCommandKeyAuthRightDesc    : NSLocalizedString(
                    @"EBAS is trying to start its web service.", 
                    @"prompt shown when user is required to authorize to start the web service"
                )
            }
        };
    });
    return sCommandInfo;
}

+ (NSString *)authorizationRightForCommand:(SEL)command
    // See comment in header.
{
    return [self commandInfo][NSStringFromSelector(command)][kCommandKeyAuthRightName];
}

+ (void)enumerateRightsUsingBlock:(void (^)(NSString * authRightName, id authRightDefault, NSString * authRightDesc))block
    // Calls the supplied block with information about each known authorization right..
{
    [self.commandInfo enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        #pragma unused(key)
        #pragma unused(stop)
        NSDictionary *  commandDict;
        NSString *      authRightName;
        id              authRightDefault;
        NSString *      authRightDesc;
        
        // If any of the following asserts fire it's likely that you've got a bug 
        // in sCommandInfo.
        
        commandDict = (NSDictionary *) obj;
        assert([commandDict isKindOfClass:[NSDictionary class]]);

        authRightName = [commandDict objectForKey:kCommandKeyAuthRightName];
        assert([authRightName isKindOfClass:[NSString class]]);

        authRightDefault = [commandDict objectForKey:kCommandKeyAuthRightDefault];
        assert(authRightDefault != nil);

        authRightDesc = [commandDict objectForKey:kCommandKeyAuthRightDesc];
        assert([authRightDesc isKindOfClass:[NSString class]]);

        block(authRightName, authRightDefault, authRightDesc);
    }];
}
```
Cela signifie qu'à la fin de ce processus, les autorisations déclarées dans `commandInfo` seront stockées dans `/var/db/auth.db`. Notez comment vous pouvez trouver pour **chaque méthode** qui nécessitera une **authentification**, le **nom de la permission** et le **`kCommandKeyAuthRightDefault`**. Ce dernier **indique qui peut obtenir ce droit**.

Il existe différents domaines pour indiquer qui peut accéder à un droit. Certains d'entre eux sont définis dans [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) (vous pouvez trouver [tous ici](https://www.dssw.co.uk/reference/authorization-rights/)), mais en résumé :

<table><thead><tr><th width="284.3333333333333">Nom</th><th width="165">Valeur</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>N'importe qui</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Personne</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>L'utilisateur actuel doit être un administrateur (dans le groupe admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Demandez à l'utilisateur de s'authentifier.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Demandez à l'utilisateur de s'authentifier. Il doit être un administrateur (dans le groupe admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Spécifiez des règles</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Spécifiez des commentaires supplémentaires sur le droit</td></tr></tbody></table>

### Vérification des droits

Dans `HelperTool/HelperTool.m`, la fonction **`readLicenseKeyAuthorization`** vérifie si l'appelant est autorisé à **exécuter une telle méthode** en appelant la fonction **`checkAuthorization`**. Cette fonction vérifiera si les **authData** envoyées par le processus appelant ont un **format correct** et vérifiera ensuite **ce qui est nécessaire pour obtenir le droit** d'appeler la méthode spécifique. Si tout se passe bien, l'**erreur renvoyée sera `nil`** :
```objectivec
- (NSError *)checkAuthorization:(NSData *)authData command:(SEL)command
{
    [...]

    // First check that authData looks reasonable.
    
    error = nil;
    if ( (authData == nil) || ([authData length] != sizeof(AuthorizationExternalForm)) ) {
        error = [NSError errorWithDomain:NSOSStatusErrorDomain code:paramErr userInfo:nil];
    }
    
    // Create an authorization ref from that the external form data contained within.
    
    if (error == nil) {
        err = AuthorizationCreateFromExternalForm([authData bytes], &authRef);
        
        // Authorize the right associated with the command.
        
        if (err == errAuthorizationSuccess) {
            AuthorizationItem   oneRight = { NULL, 0, NULL, 0 };
            AuthorizationRights rights   = { 1, &oneRight };

            oneRight.name = [[Common authorizationRightForCommand:command] UTF8String];
            assert(oneRight.name != NULL);
            
            err = AuthorizationCopyRights(
                authRef,
                &rights,
                NULL,
                kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
                NULL
            );
        }
        if (err != errAuthorizationSuccess) {
            error = [NSError errorWithDomain:NSOSStatusErrorDomain code:err userInfo:nil];
        }
    }

    if (authRef != NULL) {
        junk = AuthorizationFree(authRef, 0);
        assert(junk == errAuthorizationSuccess);
    }

    return error;
}
```
Notez que pour **vérifier les exigences pour obtenir le droit** d'appeler cette méthode, la fonction `authorizationRightForCommand` vérifiera simplement l'objet précédemment commenté **`commandInfo`**. Ensuite, elle appellera **`AuthorizationCopyRights`** pour vérifier **si elle a les droits** pour appeler la fonction (notez que les indicateurs permettent une interaction avec l'utilisateur).

Dans ce cas, pour appeler la fonction `readLicenseKeyAuthorization`, le `kCommandKeyAuthRightDefault` est défini à `@kAuthorizationRuleClassAllow`. Ainsi, **n'importe qui peut l'appeler**.

### Informations de la base de données

Il a été mentionné que ces informations sont stockées dans `/var/db/auth.db`. Vous pouvez lister toutes les règles stockées avec:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Ensuite, vous pouvez lire qui peut accéder au droit avec:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
