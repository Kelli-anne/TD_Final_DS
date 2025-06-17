# Etape 3 : Enrichissement des CVE
import requests

# Identifiant CVE à tester
cve_id = "CVE-2025-4427" #je ne sais pas s'il faut en mettre plusieurs et comment faire

# URL de l’API MITRE
url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
response = requests.get(url)
data = response.json()

# Extraire la description
try:
    description = data["containers"]["cna"]["descriptions"][0]["value"]
except:
    description = "Non disponible"

# Extraire le score CVSS
cvss_score = "Non disponible"
try:
    cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
except:
    try:
        cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"]
    except:
        pass

# Extraire le type de vulnérabilité (CWE)
cwe = "Non disponible"
cwe_desc = "Non disponible"
problemtype = data["containers"]["cna"].get("problemTypes", [])

if problemtype and "descriptions" in problemtype[0]:
    cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
    cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")

# Extraire les produits affectés
try:
    affected = data["containers"]["cna"]["affected"]
    for product in affected:
        vendor = product["vendor"]
        product_name = product["product"]
        versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
        print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
except:
    print("Aucun produit affecté trouvé.")

# Affichage
print(f"CVE : {cve_id}")
print(f"Description : {description}")
print(f"Score CVSS : {cvss_score}")
print(f"Type CWE : {cwe}")
print(f"CWE Description : {cwe_desc}")

#API EPSS
# Identifiant CVE à tester
cve_id = "CVE-2023-46805"

# URL de l’API EPSS
url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
response = requests.get(url)
data = response.json()

# Extraire le score EPSS
epss_data = data.get("data", [])
if epss_data:
    epss_score = epss_data[0]["epss"]
    print(f"CVE : {cve_id}")
    print(f"Score EPSS : {epss_score}")
else:
    print(f"Aucun score EPSS trouvé pour {cve_id}")
