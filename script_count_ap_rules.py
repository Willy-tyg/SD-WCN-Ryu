# script_count_ap_rules.py

import re

# fichier contenant la sortie de dpctl dump-flows
input_file = "flows.txt"
output_file = "ap_rules_count.txt"

ap_counts = {}  # dictionnaire pour stocker le nombre de règles par AP
current_ap = None

with open(input_file, "r") as f:
    for line in f:
        line = line.strip()
        # Détecter le nom de l'AP
        ap_match = re.match(r"\*\*\* (ap\d+) -+", line)
        if ap_match:
            current_ap = ap_match.group(1)
            ap_counts[current_ap] = 0
            continue
        
        # Ignorer les lignes vides
        if not line:
            continue

        # Compter les règles (toutes les lignes qui ne sont pas le titre de l'AP)
        if current_ap:
            ap_counts[current_ap] += 1

# Écrire le résultat dans un fichier
with open(output_file, "w") as f:
    for ap, count in ap_counts.items():
        f.write(f"{ap}: {count - 2} règles\n")


print(f"Nombre de règles par AP écrit dans {output_file}")
