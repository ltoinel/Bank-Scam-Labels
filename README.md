# Bank Scam Labels

Référentiel ouvert de libellés de transactions bancaires suspectes en France : prélèvements SEPA non autorisés, abonnements cachés par carte, faux avis de débit. Chaque entrée cite ses sources publiques et fournit un motif regex, des montants typiques et des signaux de scoring.

*Open referential of suspicious French bank transaction labels (unauthorized SEPA direct debits, hidden card subscriptions), with public sources, regex patterns and scoring signals.*

> **Un match n'est pas une preuve de fraude.** Ce référentiel produit des signaux à présenter à l'utilisateur (« libellé signalé par d'autres victimes »), jamais un verdict. Aucune entrée n'affirme qu'une société est frauduleuse.

## Pourquoi ce référentiel

Les arnaques aux prélèvements et aux abonnements cachés laissent une trace identifiable sur les relevés : un créancier SEPA inconnu, un libellé de site étranger après un paiement de 1 €, un montant récurrent typique. Ces informations sont aujourd'hui dispersées entre forums, articles de presse et sites de signalement. Ce projet les rassemble dans un format structuré, lisible par une machine, que n'importe quelle application de gestion de budget peut intégrer.

Il a été créé pour [Carbure](https://carbure.org/), plateforme open source de gestion de budget familial, et il est ouvert à tout autre outil.

## Contenu

| Fichier | Périmètre |
|---|---|
| `bsl-fr.yaml` | France, version 1 |

Le fichier est organisé en sections :

| Section | Rôle |
|---|---|
| `normalization` | Étapes de nettoyage à appliquer au libellé brut avant tout matching |
| `categories` | Types d'arnaques, avec description et recours possibles |
| `entries` | Créanciers ou marchands précis signalés publiquement (`type: label`) |
| `heuristics` | Motifs génériques pondérés, à combiner avec le contexte |
| `contextual_signals` | Signaux non textuels à calculer sur l'historique du compte |
| `score_thresholds` | Seuils d'information et d'alerte |
| `allowlist` | Libellés officiels souvent usurpés, qui neutralisent les heuristiques |
| `phishing_campaigns` | Campagnes sans ligne sur le relevé, pour les contenus pédagogiques |
| `resources` | Services officiels de signalement à proposer à l'utilisateur |

### Catégories

| Clé | Description |
|---|---|
| `unauthorized_sepa_debit` | Prélèvement SEPA émis sans mandat à partir d'IBAN issus de fuites de données |
| `hidden_subscription` | Petit paiement initial par carte sur un faux site, suivi de débits récurrents |
| `opaque_subscription` | Service réel dont l'abonnement est peu visible, pratique contestée |
| `account_test` | Micro-opération qui vérifie qu'un IBAN ou une carte est actif |
| `debit_phishing` | Faux avis de prélèvement ou de virement envoyé par mail ou SMS |

### Format d'une entrée

```yaml
- id: sepa-ens                      # identifiant stable (kebab-case)
  type: label                       # label | heuristic
  channel: sepa_debit               # card | sepa_debit | incoming_transfer | paypal | all
  category: unauthorized_sepa_debit
  pattern: '^ENS( |$)'              # regex sur le libellé normalisé
  examples: ["Prélèvement européen de ENS"]
  typical_amounts: [{ min: 300, max: 1200 }]
  confidence: high                  # low | medium | high (fiabilité du signal, pas gravité)
  status: reported                  # reported | active | obsolete
  first_seen: "2023-04"
  sources: [https://...]
  false_positives: ["..."]          # cas légitimes connus qui pourraient matcher
  advice: "Message affichable à l'utilisateur"
```

## Utilisation

1. **Déduisez le canal** (`card`, `sepa_debit`, `incoming_transfer`, `paypal`) à partir du libellé brut, avant toute normalisation.
2. **Normalisez le libellé** en suivant les étapes de `normalization` : majuscules, suppression des accents et de la ponctuation, retrait des préfixes bancaires (`PRLV SEPA`, `PAIEMENT PAR CARTE`…), des dates et des fragments de carte.
3. **Cherchez les correspondances** dans `entries` et `heuristics`, en filtrant sur le canal (une entrée en `channel: all` s'applique à tous les canaux). Vérifiez ensuite `allowlist`.
4. **Calculez un score** en cumulant les poids (`weight`) des heuristiques et des signaux contextuels, puis comparez-le à `score_thresholds` : à partir de 2, posez la question « Vous reconnaissez cette opération ? » ; à partir de 4, signalez une opération ressemblant à une arnaque connue.
5. **Affichez le message `advice`** et les `resources` adaptées, jamais une accusation.

Les regex n'utilisent ni lookbehind ni flags inline : elles fonctionnent telles quelles en JavaScript, Python, Java et Go (RE2).

### Exemple en Python

```python
import re
import unicodedata
import yaml

with open("bsl-fr.yaml", encoding="utf-8") as f:
    ref = yaml.safe_load(f)

def normalize(label: str) -> str:
    s = label.upper()
    s = "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")
    for step in ref["normalization"]["steps"]:
        if isinstance(step, dict) and "replace" in step:
            s = re.sub(step["replace"]["from"], step["replace"]["to"], s)
        elif isinstance(step, dict) and "strip_prefixes" in step:
            for p in step["strip_prefixes"]:
                s = re.sub(p, "", s).strip()
        elif isinstance(step, dict) and "strip_patterns" in step:
            for p in step["strip_patterns"]:
                s = re.sub(p, "", s)
    return re.sub(r"\s+", " ", s).strip()

def match(label: str):
    norm = normalize(label)
    hits = [e for e in ref["entries"] if re.search(e["pattern"], norm)]
    hits += [h for h in ref["heuristics"] if re.search(h["pattern"], norm)]
    return norm, hits

norm, hits = match("PAIEMENT PAR CARTE X1234 HPY*F-AUTO.CO 12/10")
print(norm, [h["id"] for h in hits])
# HPY*F AUTO CO ['cb-f-auto-co', 'h-processeur-domaine-etranger']
```

Cet exemple ne filtre pas sur le canal et ne calcule pas de score : il montre seulement la normalisation et le matching.

## Contribuer

Les contributions sont bienvenues, par pull request ou par issue. Pour qu'une entrée soit acceptée :

- **Citez au moins une source publique** (article de presse, site officiel, signalement sur un forum ou sur Signal-Arnaques). Les témoignages privés ne suffisent pas.
- **Utilisez le statut `reported`** par défaut. Le référentiel décrit des signalements, pas des condamnations.
- **Renseignez `false_positives`** dès qu'un commerçant légitime pourrait correspondre au motif.
- **Testez votre regex** sur les libellés de `examples`, après normalisation, et vérifiez sa portabilité (pas de lookbehind, pas de flags inline).
- **Mettez à jour `updated_at`** en tête de fichier.

Pour marquer une entrée comme `obsolete` (créancier disparu, campagne terminée), ouvrez une pull request avec une source qui l'atteste.

## Contestation et retrait

Si vous représentez une entreprise et estimez qu'une entrée vous concerne à tort, ouvrez une issue en précisant l'identifiant de l'entrée et les éléments qui justifient sa modification ou son retrait. Chaque demande est examinée.

## Avertissement

Ce référentiel est fourni à titre informatif, sans garantie d'exactitude ni d'exhaustivité. Il ne remplace ni l'avis de votre banque ni celui des autorités. En cas d'opération non autorisée, contactez votre banque au plus vite : vous disposez de 13 mois pour contester un prélèvement non autorisé.

Pour signaler une fraude :

- [Perceval](https://www.service-public.fr/particuliers/vosdroits/R46526) pour une fraude à la carte bancaire
- [Cybermalveillance.gouv.fr](https://www.cybermalveillance.gouv.fr/) pour une assistance
- [33700](https://www.33700.fr/) pour les SMS et appels frauduleux

## Licence

[MIT](LICENSE) © Ludovic Toinel
