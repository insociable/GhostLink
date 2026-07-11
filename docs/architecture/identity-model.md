# Modèle d’identité GhostLink

Statut : Brouillon  
Version : 0.1  
Dernière mise à jour : 2026-07-10

## 1. Objectif

Ce document définit le modèle d’identité de GhostLink.

L’objectif est de séparer clairement :

- l’identité permanente de l’utilisateur ;
- ses appareils ;
- ses clés de chiffrement ;
- ses sessions ;
- les serveurs relais.

Une identité GhostLink doit rester valide même si :

- un appareil est remplacé ;
- une clé de chiffrement est renouvelée ;
- un serveur relais est remplacé ;
- un appareil est perdu ou compromis.
## 2. Les objets fondamentaux

GhostLink repose sur cinq objets principaux.

### 2.1 L'identité

Une identité représente une entité cryptographique.

Une entité peut être :

- une personne ;
- un groupe ;
- une organisation ;
- un serveur ;
- un service automatisé.

Toutes les entités utilisent le même modèle cryptographique.

Une identité est permanente.

Elle possède :

- une clé d'identité ;
- un GhostID ;
- plusieurs appareils.

Une identité n'est jamais liée à :

- un numéro de téléphone ;
- une adresse e-mail ;
- un serveur.

---

### 2.2 Le GhostID

Le GhostID est l'identifiant public d'une identité.

Il est dérivé de la clé publique d'identité.

Il est :

- unique ;
- déterministe ;
- auto-certifiant ;
- indépendant du serveur.

Le GhostID ne change jamais tant que la clé d'identité reste la même.

---

### 2.3 Les appareils

Une identité peut posséder plusieurs appareils.

Exemples :

- PC Windows
- PC Linux
- Smartphone
- Tablette

Chaque appareil possède ses propres clés cryptographiques.

Un appareil peut être ajouté ou révoqué sans modifier le GhostID.

### 2.4 Les clés cryptographiques

GhostLink sépare volontairement les rôles des différentes clés.

Une clé ne doit jamais remplir plusieurs fonctions.

Les principales catégories sont :

- clé d'identité ;
- clé d'appareil ;
- clé de session ;
- clé de message.

Cette séparation permet :

- de remplacer une clé sans modifier l'identité ;
- de révoquer un appareil sans affecter les autres ;
- de limiter l'impact d'une compromission.

---

### 2.5 Les sessions

Une session représente un canal sécurisé entre deux appareils.

Une session :

- possède ses propres secrets cryptographiques ;
- peut être détruite à tout moment ;
- ne modifie jamais l'identité des utilisateurs.

Les messages transitent uniquement à travers une session.

---

## 3. Relations entre les objets

Le modèle général est le suivant :

```text
Utilisateur
        │
        ▼
    GhostID
        │
        ▼
   Appareils
        │
        ▼
 Clés d'appareil
        │
        ▼
    Sessions
        │
        ▼
    Messages
```

Chaque niveau dépend du précédent.

En revanche, un niveau supérieur ne dépend jamais des éléments situés en dessous.
## 4. Profil signé

Le profil est séparé de l'identité cryptographique.

Il peut contenir :

- un pseudonyme ;
- un avatar ;
- une courte description ;
- des métadonnées publiques optionnelles.

Le profil est signé par la clé d'identité de la GhostEntity.

Cette signature permet de vérifier :

- que le profil appartient bien à la GhostEntity ;
- que son contenu n'a pas été modifié ;
- que le serveur n'est pas une autorité de confiance.

Le serveur peut transporter et mettre en cache le profil signé, mais il ne peut pas
le modifier sans invalider sa signature.

Une GhostEntity peut mettre à jour son profil en publiant une nouvelle version signée.

Chaque version doit contenir au minimum :

- le GhostID ;
- un numéro de version ;
- une date de création ;
- une date d'expiration optionnelle ;
- le contenu du profil ;
- la signature de l'identité.

## 5. Confiance et vérification des contacts

La validité cryptographique ne prouve pas l'identité réelle d'une entité.

GhostLink sépare :

- la validité cryptographique ;
- la vérification humaine ;
- la décision locale de communication.

### 5.1 Validité cryptographique

La validité cryptographique est déterminée automatiquement.

Elle vérifie notamment :

- la cohérence entre la clé publique et le GhostID ;
- la validité des signatures ;
- la validité des certificats d'appareil ;
- l'absence de révocation connue.

Une signature valide prouve la possession d'une clé privée, pas l'identité réelle
de son propriétaire.

### 5.2 État de vérification

Un contact possède l'un des états suivants :

- `UNVERIFIED` : l'identité cryptographique n'a pas encore été vérifiée par un canal fiable ;
- `VERIFIED` : l'empreinte ou le QR code a été comparé par un canal indépendant.

La vérification est locale à chaque utilisateur.

Le serveur ne peut pas attribuer l'état `VERIFIED`.

### 5.3 État local du contact

Un contact possède également un état local indépendant :

- `ACTIVE` : les communications sont autorisées ;
- `BLOCKED` : les communications sont refusées localement.

Un contact vérifié peut être bloqué.

Un contact non vérifié peut être actif, mais l'interface doit afficher clairement
l'absence de vérification.

### 5.4 Principe de prudence

GhostLink ne doit jamais présenter une signature valide comme une preuve d'identité
humaine ou organisationnelle.

La vérification cryptographique et la confiance personnelle restent deux notions
distinctes.

# 6. Les dix principes de GhostLink

## 1. L'utilisateur possède son identité

Aucun serveur ne crée, ne modifie ou ne contrôle une identité.

---

## 2. Le serveur est remplaçable

La perte d'un serveur ne doit jamais entraîner la perte d'une identité.

---

## 3. Les clés privées ne quittent jamais l'appareil

Aucune clé privée n'est transmise à un serveur.

---

## 4. Le serveur transporte, il ne décide pas

Le serveur distribue des données.

Il n'est jamais une autorité de confiance.

---

## 5. Toute donnée importante est signée

Une donnée critique doit pouvoir être vérifiée indépendamment du serveur.

---

## 6. Les algorithmes sont versionnés

Aucun format ne doit empêcher une évolution future.

---

## 7. Les protocoles sont ouverts

Le protocole GhostLink est documenté publiquement.

Toute personne peut créer un client compatible.

---

## 8. La sécurité prime sur le confort

Une fonctionnalité pratique ne doit jamais réduire la sécurité globale.

---

## 9. Les métadonnées doivent être minimisées

GhostLink collecte uniquement les informations strictement nécessaires au fonctionnement.

---

## 10. Le projet appartient à la communauté

GhostLink est développé publiquement.

Les décisions d'architecture sont documentées.