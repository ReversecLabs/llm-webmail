from transformers import pipeline

pipe = pipeline("text-classification", model="leolee99/InjecGuard")

def inject_guard_detect_prompt_injection(data: list):
    """
    Detects prompt injection based on the score from the pipe result.
    
    Args:
        data (list): Input data to be processed by the pipe.
        threshold (float): The score threshold to classify as injection.
        
    Returns:
        bool: True if the score is greater than or equal to the threshold, False otherwise.
    """
    result = pipe(data)
    if result and 'label' in result[0]:  
        return result[0]['label'] == "injection"
    return False  

