# ASC - Web Application Security Control

Demo Video: https://drive.google.com/file/d/1cmTaLhdpZxnOwpVpbWx5CmBCCZwHgMY-/view?usp=sharing

A "smart" DDS (Data Distribution Service) publish/subscribe system providing real-time alerts about web application security vulnerabilities, with SPARQL-based querying and multiple output formats.

## Features

- **Real-time Security Alerts**: DDS publish/subscribe system for instant vulnerability notifications
- **Exploit-DB Integration**: Automated ingestion of web application exploits
- **Software Classification**: Filter by CMS, frameworks, modules, shopping carts, etc.
- **WebSub Support**: W3C WebSub specification for push notifications
- **SPARQL Endpoint**: Query security data using SPARQL
- **Multiple Output Formats**:
  - HTML + RDFa
  - JSON-LD (schema.org SoftwareApplication/SoftwareSourceCode)
- **Smart Caching Proxy**: Efficient data caching and retrieval

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ASC System Architecture                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │  Exploit-DB  │───>│   Ingestion  │───>│    RDF Triple Store  │   │
│  │    Scraper   │    │   Service    │    │   (SPARQL Endpoint)  │   │
│  └──────────────┘    └──────────────┘    └──────────────────────┘   │
│                              │                       │               │
│                              ▼                       ▼               │
│                    ┌──────────────┐         ┌──────────────┐        │
│                    │  DDS Pub/Sub │<───────>│   REST API   │        │
│                    │    System    │         │  (FastAPI)   │        │
│                    └──────────────┘         └──────────────┘        │
│                           │                                          │
│              ┌────────────┼────                                      │
│              ▼            ▼                                          │
│       ┌──────────┐ ┌──────────┐                                     │
│       │ WebSub   │ │WebSocket │                                     │
│       │   Hub    │ │  Alerts  │                                     │
│       └──────────┘ └──────────┘                                     │
│                                                                      │
│  Output Formats: HTML+RDFa │ JSON-LD │ Turtle │ N-Triples           │
└─────────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python -m asc.init_db

# Start the server
python -m asc.main
```

## Configuration

Create a `.env` file in the project root:

```env
ASC_DATABASE_URL=sqlite+aiosqlite:///./asc.db
ASC_CACHE_TTL=300
```

## API Endpoints

### REST API

| Endpoint             | Method | Description                      |
| -------------------- | ------ | -------------------------------- |
| `/api/exploits`      | GET    | List all exploits with filtering |
| `/api/exploits/{id}` | GET    | Get exploit details              |
| `/api/subscribe`     | POST   | Subscribe to alerts              |
| `/api/categories`    | GET    | List software categories         |

### SPARQL Endpoint

- **Endpoint**: `/sparql`
- **Query Parameter**: `query` (SPARQL query string)

Example query:

```sparql
PREFIX asc: <http://asc.example.org/ontology#>
PREFIX schema: <https://schema.org/>

SELECT ?exploit ?title ?platform ?date
WHERE {
  ?exploit a asc:WebExploit ;
           schema:name ?title ;
           asc:platform ?platform ;
           schema:datePublished ?date .
  FILTER(CONTAINS(LCASE(?platform), "php"))
}
ORDER BY DESC(?date)
LIMIT 10
```

### WebSub Hub

- **Hub URL**: `/websub/hub`
- **Topic Discovery**: `/websub/topic/{category}`

## Output Formats

### JSON-LD Example

```json
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "WordPress Plugin Exploit",
  "softwareVersion": "5.0.0",
  "operatingSystem": "PHP",
  "securityIssue": {
    "@type": "SecurityAdvisory",
    "severity": "High",
    "description": "SQL Injection vulnerability"
  }
}
```

### HTML + RDFa

The web interface includes semantic markup using RDFa attributes for machine-readable data.

## WebSub (W3C Specification)

This system implements WebSub (formerly PubSubHubbub) for real-time notifications:

1. **Publisher**: Announces new vulnerabilities
2. **Hub**: Manages subscriptions and delivers updates
3. **Subscriber**: Receives push notifications
