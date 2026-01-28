🛡️ PhishScan: Automated Email Triage Tool
Jump to Spanish Version / Saltar a la versión en Español

📋 Overview (The "Elevator Pitch")
PhishScan Pro is a Python-based security tool designed to automate the initial analysis of suspicious emails (.eml files). Instead of manually inspecting raw code, this tool performs a "digital autopsy" of the message to determine its legitimacy. It cross-references hidden data (like origin IPs and link reputations) against global threat databases to provide a clear risk verdict in seconds.

🛠️ Technical Features
Multi-Layered Header Analysis: Detects Domain Mismatch (Spoofing) by comparing the From field with the Return-Path.

Resilient IP Extraction: Implements a failover logic to find the true source IP, scanning both Received hops and specific headers like X-Sender-IP.

Automatic Base64 Decoding: Capable of reading obfuscated email bodies that standard filters might miss.

Threat Intelligence Integration: Real-time queries to AbuseIPDB for IP reputation and VirusTotal for malicious URL detection.

Interactive CLI: Simple, user-friendly interface for security analysts to process files on the fly.

🚀 Getting Started
Prerequisites
Python 3.x

Libraries: requests, mail-parser

Bash
pip install requests mail-parser
Setup
Clone the repository.

Obtain your free API Keys from AbuseIPDB and VirusTotal.

Add your keys to the ABUSE_API_KEY and VT_API_KEY variables in the script.

Versión en Español
📋 Resumen
PhishScan Pro es una herramienta de seguridad desarrollada en Python para automatizar el triaje inicial de correos electrónicos sospechosos (archivos .eml). En lugar de inspeccionar manualmente el código fuente, esta herramienta realiza una "autopsia digital" del mensaje para determinar su legitimidad. Contrasta datos ocultos (como IPs de origen y reputación de enlaces) con bases de datos globales de amenazas para ofrecer un veredicto de riesgo en segundos.

🛠️ Características Técnicas
Análisis de Cabeceras en Capas: Detecta Suplantación de Identidad (Spoofing) comparando el campo From con el Return-Path.

Extracción de IP Resiliente: Implementa una lógica de respaldo para encontrar la IP de origen real, escaneando tanto los saltos Received como cabeceras específicas (X-Sender-IP).

Decodificación Base64 Automática: Capacidad para leer cuerpos de correo ofuscados que los filtros estándar suelen pasar por alto.

Integración de Inteligencia de Amenazas: Consultas en tiempo real a AbuseIPDB para reputación de IPs y a VirusTotal para detección de URLs maliciosas.

CLI Interactivo: Interfaz sencilla y directa para que los analistas de seguridad procesen archivos rápidamente.

🚀 Instrucciones
Requisitos
Python 3.x

Librerías: requests, mail-parser

Bash
pip install requests mail-parser
Configuración
Clona el repositorio.

Consigue tus API Keys gratuitas en AbuseIPDB y VirusTotal.

Introduce tus llaves en las variables ABUSE_API_KEY y VT_API_KEY del script.

🛡️ Why this project? / ¿Por qué este proyecto?
This tool was born from the need to reduce the "mean time to respond" (MTTR) in a SOC environment. It demonstrates how automation can bridge the gap between complex network protocols and actionable security decisions.

Esta herramienta nace de la necesidad de reducir el tiempo de respuesta (MTTR) en entornos de SOC. Demuestra cómo la automatización puede conectar protocolos de red complejos con decisiones de seguridad efectivas.
