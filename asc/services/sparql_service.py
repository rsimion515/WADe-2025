"""
SPARQL Service and RDF Triple Store.

Provides a SPARQL endpoint for querying security vulnerability data
with RDF representation using schema.org vocabularies.
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any, Union
from rdflib import Graph, Namespace, Literal, URIRef, BNode
from rdflib.namespace import RDF, RDFS, XSD, FOAF, DCTERMS
from io import StringIO

from ..config import get_settings
from ..models.exploit import Exploit

logger = logging.getLogger(__name__)
settings = get_settings()

# Define namespaces
SCHEMA = Namespace("https://schema.org/")
ASC = Namespace(settings.asc_namespace)
ASC_DATA = Namespace(settings.asc_data_namespace)
CVE = Namespace("https://cve.mitre.org/cgi-bin/cvename.cgi?name=")
CWE = Namespace("https://cwe.mitre.org/data/definitions/")


class SPARQLService:
    """
    SPARQL query service with in-memory RDF triple store.
    
    Features:
    - RDF graph management
    - SPARQL query execution
    - Multiple serialization formats
    - Schema.org vocabulary support
    """
    
    # Exploit type to CWE mapping
    EXPLOIT_TO_CWE = {
        "sqli": "89",  # SQL Injection
        "xss": "79",   # Cross-site Scripting
        "rce": "94",   # Code Injection
        "lfi": "98",   # Improper Control of Filename for Include
        "rfi": "98",   # Remote File Inclusion
        "csrf": "352", # Cross-Site Request Forgery
        "auth_bypass": "287", # Improper Authentication
        "file_upload": "434", # Unrestricted Upload
        "ssrf": "918", # Server-Side Request Forgery
        "xxe": "611",  # Improper Restriction of XML External Entity Reference
        "deserialization": "502", # Deserialization of Untrusted Data
    }
    
    def __init__(self):
        """Initialize the SPARQL service."""
        self.graph = Graph()
        self._bind_namespaces()
        self._add_ontology()
    
    def _bind_namespaces(self):
        """Bind namespace prefixes."""
        self.graph.bind("schema", SCHEMA)
        self.graph.bind("asc", ASC)
        self.graph.bind("data", ASC_DATA)
        self.graph.bind("cve", CVE)
        self.graph.bind("cwe", CWE)
        self.graph.bind("dcterms", DCTERMS)
        self.graph.bind("foaf", FOAF)
    
    def _add_ontology(self):
        """Add ASC ontology definitions."""
        # Define ASC classes
        self.graph.add((ASC.WebExploit, RDF.type, RDFS.Class))
        self.graph.add((ASC.WebExploit, RDFS.label, Literal("Web Application Exploit")))
        self.graph.add((ASC.WebExploit, RDFS.subClassOf, SCHEMA.CreativeWork))
        
        self.graph.add((ASC.SecurityAdvisory, RDF.type, RDFS.Class))
        self.graph.add((ASC.SecurityAdvisory, RDFS.label, Literal("Security Advisory")))
        self.graph.add((ASC.SecurityAdvisory, RDFS.subClassOf, SCHEMA.Article))
        
        self.graph.add((ASC.Vulnerability, RDF.type, RDFS.Class))
        self.graph.add((ASC.Vulnerability, RDFS.label, Literal("Security Vulnerability")))
        
        # Define ASC properties
        properties = [
            (ASC.exploitType, "Exploit Type", "Type of exploit (SQLi, XSS, RCE, etc.)"),
            (ASC.severity, "Severity", "Severity level (critical, high, medium, low)"),
            (ASC.platform, "Platform", "Target platform (PHP, Java, etc.)"),
            (ASC.softwareType, "Software Type", "Type of software (CMS, framework, etc.)"),
            (ASC.affectedSoftware, "Affected Software", "Name of affected software"),
            (ASC.affectedVersion, "Affected Version", "Version of affected software"),
            (ASC.solution, "Solution", "Recommended solution"),
            (ASC.mitigation, "Mitigation", "Mitigation measures"),
            (ASC.cveId, "CVE ID", "Common Vulnerabilities and Exposures ID"),
            (ASC.cweId, "CWE ID", "Common Weakness Enumeration ID"),
            (ASC.cvssScore, "CVSS Score", "Common Vulnerability Scoring System score"),
            (ASC.proofOfConcept, "Proof of Concept", "Exploit proof of concept code"),
        ]
        
        for prop, label, description in properties:
            self.graph.add((prop, RDF.type, RDF.Property))
            self.graph.add((prop, RDFS.label, Literal(label)))
            self.graph.add((prop, RDFS.comment, Literal(description)))
    
    def add_exploit(self, exploit: Union[Exploit, Dict]) -> URIRef:
        """
        Add an exploit to the RDF graph.
        
        Args:
            exploit: Exploit object or dictionary
            
        Returns:
            URI of the created resource
        """
        if isinstance(exploit, dict):
            data = exploit
            exploit_id = data.get("id") or data.get("exploit_db_id", "unknown")
        else:
            data = {
                "id": exploit.id,
                "exploit_db_id": exploit.exploit_db_id,
                "title": exploit.title,
                "description": exploit.description,
                "platform": exploit.platform,
                "software_type": exploit.software_type,
                "exploit_type": exploit.exploit_type,
                "severity": exploit.severity,
                "software_name": exploit.software_name,
                "software_version": exploit.software_version,
                "vendor": exploit.vendor,
                "cve_id": exploit.cve_id,
                "cvss_score": exploit.cvss_score,
                "author": exploit.author,
                "exploit_code": exploit.exploit_code,
                "proof_of_concept": exploit.proof_of_concept,
                "solution": exploit.solution,
                "mitigation": exploit.mitigation,
                "source_url": exploit.source_url,
                "published_date": exploit.published_date,
            }
            exploit_id = exploit.id or exploit.exploit_db_id
        
        # Create exploit URI
        exploit_uri = ASC_DATA[f"exploit/{exploit_id}"]
        
        # Add type information
        self.graph.add((exploit_uri, RDF.type, ASC.WebExploit))
        self.graph.add((exploit_uri, RDF.type, SCHEMA.SoftwareApplication))
        
        # Add schema.org properties
        if data.get("title"):
            self.graph.add((exploit_uri, SCHEMA.name, Literal(data["title"])))
        
        if data.get("description"):
            self.graph.add((exploit_uri, SCHEMA.description, Literal(data["description"])))
        
        if data.get("author"):
            author_node = BNode()
            self.graph.add((exploit_uri, SCHEMA.author, author_node))
            self.graph.add((author_node, RDF.type, SCHEMA.Person))
            self.graph.add((author_node, SCHEMA.name, Literal(data["author"])))
        
        if data.get("published_date"):
            date_str = data["published_date"]
            if isinstance(date_str, datetime):
                date_str = date_str.isoformat()
            self.graph.add((exploit_uri, SCHEMA.datePublished, Literal(date_str, datatype=XSD.dateTime)))
        
        if data.get("source_url"):
            self.graph.add((exploit_uri, SCHEMA.url, URIRef(data["source_url"])))
        
        # Add ASC-specific properties
        if data.get("platform"):
            self.graph.add((exploit_uri, ASC.platform, Literal(data["platform"])))
        
        if data.get("software_type"):
            self.graph.add((exploit_uri, ASC.softwareType, Literal(data["software_type"])))
        
        if data.get("exploit_type"):
            self.graph.add((exploit_uri, ASC.exploitType, Literal(data["exploit_type"])))
            # Add CWE reference
            cwe_id = self.EXPLOIT_TO_CWE.get(data["exploit_type"])
            if cwe_id:
                self.graph.add((exploit_uri, ASC.cweId, URIRef(f"{CWE}{cwe_id}")))
        
        if data.get("severity"):
            self.graph.add((exploit_uri, ASC.severity, Literal(data["severity"])))
        
        if data.get("software_name"):
            self.graph.add((exploit_uri, ASC.affectedSoftware, Literal(data["software_name"])))
            self.graph.add((exploit_uri, SCHEMA.softwareRequirements, Literal(data["software_name"])))
        
        if data.get("software_version"):
            self.graph.add((exploit_uri, ASC.affectedVersion, Literal(data["software_version"])))
            self.graph.add((exploit_uri, SCHEMA.softwareVersion, Literal(data["software_version"])))
        
        if data.get("vendor"):
            vendor_node = BNode()
            self.graph.add((exploit_uri, SCHEMA.provider, vendor_node))
            self.graph.add((vendor_node, RDF.type, SCHEMA.Organization))
            self.graph.add((vendor_node, SCHEMA.name, Literal(data["vendor"])))
        
        if data.get("cve_id"):
            self.graph.add((exploit_uri, ASC.cveId, URIRef(f"{CVE}{data['cve_id']}")))
        
        if data.get("cvss_score"):
            self.graph.add((exploit_uri, ASC.cvssScore, Literal(data["cvss_score"])))
        
        if data.get("solution"):
            self.graph.add((exploit_uri, ASC.solution, Literal(data["solution"])))
        
        if data.get("mitigation"):
            self.graph.add((exploit_uri, ASC.mitigation, Literal(data["mitigation"])))
        
        if data.get("proof_of_concept") or data.get("exploit_code"):
            poc = data.get("proof_of_concept") or data.get("exploit_code")
            # Create SoftwareSourceCode for PoC
            poc_uri = ASC_DATA[f"poc/{exploit_id}"]
            self.graph.add((poc_uri, RDF.type, SCHEMA.SoftwareSourceCode))
            self.graph.add((poc_uri, SCHEMA.text, Literal(poc[:5000])))  # Limit size
            self.graph.add((exploit_uri, ASC.proofOfConcept, poc_uri))
        
        logger.debug(f"Added exploit {exploit_id} to RDF graph")
        return exploit_uri
    
    def add_exploits(self, exploits: List[Union[Exploit, Dict]]) -> List[URIRef]:
        """Add multiple exploits to the graph."""
        return [self.add_exploit(e) for e in exploits]
    
    def execute_query(self, query: str) -> List[Dict]:
        """
        Execute a SPARQL query.
        
        Args:
            query: SPARQL query string
            
        Returns:
            List of result bindings as dictionaries
        """
        try:
            results = self.graph.query(query)
            
            if results.type == "SELECT":
                return [
                    {str(var): str(row[var]) if row[var] else None for var in results.vars}
                    for row in results
                ]
            elif results.type == "ASK":
                return [{"result": bool(results)}]
            elif results.type == "CONSTRUCT":
                # Return constructed graph as turtle
                g = Graph()
                for triple in results:
                    g.add(triple)
                return [{"graph": g.serialize(format="turtle")}]
            
            return []
            
        except Exception as e:
            logger.error(f"SPARQL query error: {e}")
            raise ValueError(f"Invalid SPARQL query: {e}")
    
    def serialize(self, format: str = "turtle") -> str:
        """
        Serialize the graph to a string.
        
        Args:
            format: Output format (turtle, xml, json-ld, n3, nt)
            
        Returns:
            Serialized graph string
        """
        return self.graph.serialize(format=format)
    
    def get_exploit_jsonld(self, exploit_id: str) -> Dict:
        """
        Get a single exploit as JSON-LD.
        
        Args:
            exploit_id: Exploit identifier
            
        Returns:
            JSON-LD document
        """
        exploit_uri = ASC_DATA[f"exploit/{exploit_id}"]
        
        # Extract triples for this exploit
        subgraph = Graph()
        for p, o in self.graph.predicate_objects(exploit_uri):
            subgraph.add((exploit_uri, p, o))
            # Add nested objects
            if isinstance(o, BNode):
                for p2, o2 in self.graph.predicate_objects(o):
                    subgraph.add((o, p2, o2))
        
        if len(subgraph) == 0:
            return {}
        
        # Serialize to JSON-LD
        jsonld_str = subgraph.serialize(format="json-ld")
        return json.loads(jsonld_str)
    
    def get_schema_org_jsonld(self, exploit_id: str) -> Dict:
        """
        Get exploit as schema.org conformant JSON-LD.
        
        Args:
            exploit_id: Exploit identifier
            
        Returns:
            Schema.org JSON-LD document
        """
        query = f"""
        PREFIX schema: <https://schema.org/>
        PREFIX asc: <{settings.asc_namespace}>
        PREFIX data: <{settings.asc_data_namespace}>
        
        SELECT ?name ?description ?platform ?severity ?software ?version ?date ?url
        WHERE {{
            data:exploit/{exploit_id} schema:name ?name .
            OPTIONAL {{ data:exploit/{exploit_id} schema:description ?description }}
            OPTIONAL {{ data:exploit/{exploit_id} asc:platform ?platform }}
            OPTIONAL {{ data:exploit/{exploit_id} asc:severity ?severity }}
            OPTIONAL {{ data:exploit/{exploit_id} asc:affectedSoftware ?software }}
            OPTIONAL {{ data:exploit/{exploit_id} asc:affectedVersion ?version }}
            OPTIONAL {{ data:exploit/{exploit_id} schema:datePublished ?date }}
            OPTIONAL {{ data:exploit/{exploit_id} schema:url ?url }}
        }}
        """
        
        results = self.execute_query(query)
        
        if not results:
            return {}
        
        result = results[0]
        
        return {
            "@context": "https://schema.org",
            "@type": "SoftwareApplication",
            "name": result.get("name"),
            "description": result.get("description"),
            "operatingSystem": result.get("platform"),
            "softwareVersion": result.get("version"),
            "datePublished": result.get("date"),
            "url": result.get("url"),
            "additionalType": f"{settings.asc_namespace}WebExploit",
            "securityIssue": {
                "@type": "SecurityAdvisory",
                "severity": result.get("severity"),
                "affectedSoftware": result.get("software"),
            }
        }
    
    def get_statistics(self) -> Dict:
        """Get statistics about the RDF graph."""
        query = """
        PREFIX asc: <%s>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        
        SELECT 
            (COUNT(DISTINCT ?exploit) AS ?total_exploits)
        WHERE {
            ?exploit rdf:type asc:WebExploit .
        }
        """ % settings.asc_namespace
        
        results = self.execute_query(query)
        total = int(results[0]["total_exploits"]) if results and results[0]['total_exploits'] else 0
        
        return {
            "total_triples": len(self.graph),
            "total_exploits": total,
        }


# Global SPARQL service instance
_sparql_service: Optional[SPARQLService] = None


def get_sparql_service() -> SPARQLService:
    """Get the global SPARQL service instance."""
    global _sparql_service
    if _sparql_service is None:
        _sparql_service = SPARQLService()
    return _sparql_service


# Predefined SPARQL queries
EXAMPLE_QUERIES = {
    "all_exploits": """
PREFIX asc: <http://asc.example.org/ontology#>
PREFIX schema: <https://schema.org/>

SELECT ?exploit ?title ?platform ?severity ?date
WHERE {
    ?exploit a asc:WebExploit ;
             schema:name ?title .
    OPTIONAL { ?exploit asc:platform ?platform }
    OPTIONAL { ?exploit asc:severity ?severity }
    OPTIONAL { ?exploit schema:datePublished ?date }
}
ORDER BY DESC(?date)
LIMIT 50
""",
    
    "critical_exploits": """
PREFIX asc: <http://asc.example.org/ontology#>
PREFIX schema: <https://schema.org/>

SELECT ?exploit ?title ?software ?type
WHERE {
    ?exploit a asc:WebExploit ;
             schema:name ?title ;
             asc:severity "critical" .
    OPTIONAL { ?exploit asc:affectedSoftware ?software }
    OPTIONAL { ?exploit asc:exploitType ?type }
}
""",
    
    "cms_vulnerabilities": """
PREFIX asc: <http://asc.example.org/ontology#>
PREFIX schema: <https://schema.org/>

SELECT ?exploit ?title ?software ?severity
WHERE {
    ?exploit a asc:WebExploit ;
             schema:name ?title ;
             asc:softwareType "cms" .
    OPTIONAL { ?exploit asc:affectedSoftware ?software }
    OPTIONAL { ?exploit asc:severity ?severity }
}
ORDER BY ?severity
""",
    
    "sqli_with_solutions": """
PREFIX asc: <http://asc.example.org/ontology#>
PREFIX schema: <https://schema.org/>

SELECT ?exploit ?title ?solution ?mitigation
WHERE {
    ?exploit a asc:WebExploit ;
             schema:name ?title ;
             asc:exploitType "sqli" .
    OPTIONAL { ?exploit asc:solution ?solution }
    OPTIONAL { ?exploit asc:mitigation ?mitigation }
}
""",
}
