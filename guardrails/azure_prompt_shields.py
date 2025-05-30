import os
import requests
from dotenv import load_dotenv

load_dotenv()

def azure_detect_prompt_injection(document: str) -> bool:
    subscription_key = os.getenv("AZURE_AI_CONTENT_SAFETY_KEY")
    endpoint = os.getenv("AZURE_AI_CONTENT_SAFETY_ENDPOINT")
    api_version = "2024-09-01"
    headers = {"Content-Type": "application/json", "Ocp-Apim-Subscription-Key": subscription_key}
    url = f"{endpoint}/contentsafety/text:shieldPrompt?api-version={api_version}"
    body = {"userPrompt": "", "documents": [document]}
    resp = requests.post(url, headers=headers, json=body)
    if resp.status_code == 200:
        data = resp.json()
        document_analysis = data.get('documentsAnalysis', [{}])[0]        
        return document_analysis.get('attackDetected', False)
    raise Exception(f"Azure Shield Error {resp.status_code}: {resp.text}")