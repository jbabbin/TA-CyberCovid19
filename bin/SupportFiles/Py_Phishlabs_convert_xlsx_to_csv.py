import rows
data = rows.import_from_xlsx("Phishlabs_Malicious_URLs.xlsx")
rows.export_to_csv(data, open("Phishlabs_Malicious_URLs.csv", "wb"))
