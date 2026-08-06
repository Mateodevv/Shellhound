---
name: Add Hunt Pattern to default Library
about: Describe this issue template's purpose here.
title: ''
labels: ''
assignees: Mateodevv

---

---
name: 🎯 New Hunt Pattern
about: Submit a new hunt pattern for detection, analysis, or monitoring
title: "[PATTERN] - <Insert Pattern Name Here>"
labels: 'hunt-pattern, enhancement'
assignees: ''
---

<!-- 
Thank you for submitting a new Hunt Pattern! 
Please fill out the sections below to provide the necessary context. 
-->

### 📛 Name of the Hunt Pattern
<!-- Replace the text below with the exact name of the pattern -->
**[Insert Pattern Name]**

---

### 📝 Short Description
<!-- Provide a concise 1-2 sentence description of what this pattern hunts for and why it matters. -->
> [Insert 1-2 sentences explaining the behavior, exploit, or anomaly this pattern is designed to catch]

---

### 🐛 Matching CVE(s)
<!-- If applicable, list the CVE(s) associated with this pattern. If none, write "N/A". -->
- **CVE-YYYY-NNNNN**

---

### 🔗 URL-Pattern
<!-- Provide the URL structure used for the hunt. Use the code block below so special characters aren't parsed by Markdown! -->
```regex
# Insert your URL pattern
^/example/path/.*\.php\?id=[0-9]+
