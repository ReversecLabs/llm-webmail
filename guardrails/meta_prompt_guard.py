from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer
)
import torch
from torch.nn.functional import softmax
from dotenv import load_dotenv

load_dotenv()

prompt_injection_model_name = 'meta-llama/Prompt-Guard-86M'
tokenizer = None
model = None

def _ensure_model_loaded():
    global tokenizer, model
    if tokenizer is None or model is None:
        tokenizer = AutoTokenizer.from_pretrained(prompt_injection_model_name)
        model = AutoModelForSequenceClassification.from_pretrained(prompt_injection_model_name)

def get_class_probabilities(text, temperature=1.0, device='cpu'):
    _ensure_model_loaded()
    inputs = tokenizer(text, return_tensors="pt", padding=True, truncation=True, max_length=512)
    inputs = inputs.to(device)
    with torch.no_grad():
        logits = model(**inputs).logits
    scaled_logits = logits / temperature
    probabilities = softmax(scaled_logits, dim=-1)
    return probabilities

def get_jailbreak_score(text, temperature=1.0, device='cpu'):
    probabilities = get_class_probabilities(text, temperature, device)
    return probabilities[0, 2].item()

def get_indirect_injection_score(text, temperature=1.0, device='cpu'):
    probabilities = get_class_probabilities(text, temperature, device)
    return (probabilities[0, 1] + probabilities[0, 2]).item()

def meta_scan_for_injections(input_text, system_message=None):
    try:
        score = get_indirect_injection_score(input_text)
        attack_detected = score > 0.5
        return attack_detected
    except Exception as e:
        raise e
