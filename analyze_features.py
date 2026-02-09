import json

data = json.load(open('phishing_detection_results.json', encoding='utf-8'))
features = {}

for email in data:
    for f, info in email['features'].items():
        if f not in features:
            features[f] = 0
        if info['score'] > 0:
            features[f] += 1

total = len(data)
print(f"\nFeature Trigger Frequency (out of {total} emails):\n")
for f, count in sorted(features.items(), key=lambda x: x[1]):
    pct = count/total*100
    print(f"{f:35} {count:2}/{total} ({pct:5.1f}%)")
