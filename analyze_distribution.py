import json

# Read JSON results
with open('phishing_detection_results.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Analyze probability distribution
probabilities = [email['phish_probability'] for email in data]
total = len(probabilities)

# Count by risk level
critical = sum(1 for p in probabilities if p >= 85)
high = sum(1 for p in probabilities if 70 <= p < 85)
medium = sum(1 for p in probabilities if 50 <= p < 70)
low = sum(1 for p in probabilities if 30 <= p < 50)
minimal = sum(1 for p in probabilities if p < 30)

# Calculate average
avg = sum(probabilities) / total

print(f"\n=== FULL DATASET ANALYSIS ({total} emails) ===\n")
print(f"Average Phish Probability: {avg:.2f}%\n")
print("Distribution by Risk Level:")
print(f"  CRITICAL (>=85%): {critical:5d} / {total} ({critical/total*100:5.2f}%)")
print(f"  HIGH (70-84%):    {high:5d} / {total} ({high/total*100:5.2f}%)")
print(f"  MEDIUM (50-69%):  {medium:5d} / {total} ({medium/total*100:5.2f}%)")
print(f"  LOW (30-49%):     {low:5d} / {total} ({low/total*100:5.2f}%)")
print(f"  MINIMAL (<30%):   {minimal:5d} / {total} ({minimal/total*100:5.2f}%)")
print(f"\nHIGH + CRITICAL:    {critical+high:5d} / {total} ({(critical+high)/total*100:5.2f}%)")

# Show score quartiles
sorted_probs = sorted(probabilities)
print(f"\nQuartiles:")
print(f"  Min:  {sorted_probs[0]:.2f}%")
print(f"  Q1:   {sorted_probs[len(sorted_probs)//4]:.2f}%")
print(f"  Q2:   {sorted_probs[len(sorted_probs)//2]:.2f}%")
print(f"  Q3:   {sorted_probs[3*len(sorted_probs)//4]:.2f}%")
print(f"  Max:  {sorted_probs[-1]:.2f}%")
