#Ce script permet de combiner deux fichiers CSV contenant des données enrichies sur des vulnérabilités CVE
# provenant de bulletins ANSSI. Les fichiers sont :
#- cve_ansi_enriched_requete.csv : nous avons fait des requêtes directement sur le site pour récupérer des données
#- cves_enriched_local.csv : utilisation du fichier donné pour le projet
# Le fichier cves-concat.csv réunit les 2 entrées.

import pandas as pd

df1 = pd.read_csv("cve_ansi_enriched_requete.csv")
df2 = pd.read_csv("cves_enriched_local.csv")

df_concat = pd.concat([df1, df2], ignore_index=True)
df_concat = df_concat.drop_duplicates()
df_concat.to_csv("cves_concat.csv", index=False)

print("Concaténation terminée ! Résultat dans 'cves_concat.csv'.")
