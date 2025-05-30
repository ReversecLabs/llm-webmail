import boto3
import json
import os
from botocore.exceptions import ClientError
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

bedrock_runtime = boto3.client('bedrock-runtime', region_name='us-east-1')

# Specific guardrail ID and version
guardrail_id = os.getenv("AWS_GUARDRAIL_ID") 

def aws_detect_prompt_injection(data):
    content = [
        {
            "text": {
                "text": data
            }
        }
    ]
    try:
        response = bedrock_runtime.apply_guardrail(
            guardrailIdentifier=guardrail_id,
            guardrailVersion="DRAFT",
            source='INPUT', 
            content=content
        )
        
        # Check the action taken by the guardrail
        if response['action'] == 'GUARDRAIL_INTERVENED':
            # Inspect assessments for the specific filter
            assessments = response.get('assessments', [])
            for assessment in assessments:
                content_policy = assessment.get('contentPolicy', {})
                filters = content_policy.get('filters', [])
                for filter_entry in filters:
                    if (
                        filter_entry.get('type') == 'PROMPT_ATTACK' and
                        filter_entry.get('action') == 'BLOCKED'
                    ):
                        return True  # Return True only if criteria are met
    except Exception as e:
        print(f"An error occurred: {str(e)}")
      
    return False 


