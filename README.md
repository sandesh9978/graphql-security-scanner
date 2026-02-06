# 🚀 GraphQL Security Scanner

A Python-based **GraphQL security scanner** for testing GraphQL APIs for vulnerabilities, introspection leaks, and misconfigurations. Perfect for learning, testing, and improving API security.

---

## 🧩 Project Structure

graphql-security-scanner/
│
├── graphql_scanner.py # Core scanner logic
├── test_graphql_scanner.py # Unit tests for scanner functionality
└── README.md # This file


- `graphql_scanner.py`: Sends queries, analyzes responses, and reports security findings.
- `test_graphql_scanner.py`: Ensures reliability and correctness using automated tests.
- `README.md`: Explains how the tool works and how to use it.

---

## 🔐 Features

- ✅ Detects **GraphQL introspection** exposure  
- ✅ Identifies common tables like Users, Products, Posts, and Paste objects  
- ✅ Tests **rate limiting** and **batch query support**  
- ✅ Checks for **Denial of Service (DoS) vulnerabilities**  
- ✅ Logs results and optionally encrypts them for safe storage  

---

## ⚡ Installation

1. Clone this repository:

```bash
git clone https://github.com/<your-username>/graphql-security-scanner.git
cd graphql-security-scanner
Install dependencies:

pip install -r requirements.txt
# If no requirements.txt, install manually:
pip install requests cryptography
🖥️ Usage
Run the scanner:

python graphql_scanner.py
Enter the target GraphQL URL in the GUI.

Use the buttons to perform:

Recon: Check introspection and schema

Exploit: Attempt safe extraction of common patterns

DoS Test: Test for heavy nested query handling

Batch: Test batch query support

Rate: Test for rate limiting

Save logs securely with a password, or decrypt previously saved logs.

🧪 Running Tests
The project comes with a complete test suite:

python test_graphql_scanner.py
The tests cover:

Password hashing and verification

Encryption key derivation

GraphQL endpoint detection

Introspection parsing

Exploit attempts simulation

DoS, batch, and rate limit tests

📌 Security Notes
This tool is for learning and testing only.

Never scan APIs without permission. Unauthorized scanning may be illegal.

All exploit attempts are read-only and safe, but always confirm permissions.

🤝 Contributing
Fork the repository

Create your feature branch: git checkout -b feature/YourFeature

Commit your changes: git commit -m "Add new feature"

Push to branch: git push origin feature/YourFeature

Open a Pull Request

📄 License
This project uses the MIT License.
You are free to use, modify, and distribute this project with attribution.

💡 Learning Outcomes
By using or contributing to this project, you’ll learn:

How GraphQL APIs handle queries and introspection

How to detect potential security misconfigurations

How to write Python code with testing and encryption

How to structure small but professional security tools

