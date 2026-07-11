# Spécification du certificat d’appareil GhostLink

Statut : Brouillon  
Version : 0.1

## 1. Objectif

Un certificat d’appareil permet de prouver qu’un appareil a été autorisé par une GhostEntity.

Le certificat lie cryptographiquement :

- une GhostEntity ;
- un appareil ;
- une clé publique de signature ;
- une clé publique de chiffrement ;
- une période de validité.

Le serveur relais peut transporter et stocker ce certificat, mais il ne peut pas le créer ou le modifier sans invalider sa signature.

## 2. Principes de sécurité

Un certificat d’appareil doit respecter les propriétés suivantes :

1. Il est signé par la clé d’identité de la GhostEntity.
2. Il ne contient aucune clé privée.
3. Il possède un format versionné.
4. Il peut expirer.
5. Il peut être révoqué.
6. Il reste vérifiable sans faire confiance au serveur.
7. Sa représentation signée doit être déterministe.