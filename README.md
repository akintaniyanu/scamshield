# 🛡️ ScamShield

ScamShield is a lightweight cybersecurity tool that helps users assess suspicious URLs, messages, email addresses, and phone numbers before interacting with them.

## The Problem

People receive suspicious links and messages every day.

The problem is that many people don't know whether something is legitimate until after they have already clicked a link, entered their credentials, transferred money, or shared personal information.

ScamShield provides an initial risk assessment based on observable indicators.

## Features

- URL risk analysis
- Suspicious message analysis
- Email address analysis
- Phone number analysis
- Explainable risk scoring
- Scan history
- Security dashboard
- REST API
- Input validation
- Security headers
- Rate limiting
- SQLite database

## Risk Levels

🟢 LOW RISK

No major warning indicators were detected.

🟡 SUSPICIOUS

One or more warning indicators were detected.

🔴 HIGH RISK

Multiple strong warning indicators were detected.

## How It Works

User Input

↓

Input Validation

↓

Analysis Engine

↓

Risk Scoring

↓

Explanation

↓

SQLite Database

## Technology Stack

- Python
- Flask
- SQLite
- HTML
- CSS
- DNS analysis
- RDAP domain information

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/scamshield.git
cd scamshield
