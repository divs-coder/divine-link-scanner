from scanner import analyze_url

url = input("Enter a URL: ")

result = analyze_url(url)

print("\n--- LINK ANALYSIS ---")
print("URL:", result["url"])
print("Risk Score:", result["risk_score"], "/ 100")
print("Risk Level:", result["risk_level"])

print("\nReasons:")

if result["reasons"]:
    for reason in result["reasons"]:
        print("-", reason)
else:
    print("- No basic warning signs detected.")
