import os
import json
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, Any, Optional, List, Union

# Required environment variables for using this LLM client
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

class LLMClient:
    """
    A client for interacting with LLM APIs, currently supporting OpenAI's GPT-4.
    """
    
    def __init__(
        self, 
        base_url: str = "https://api.openai.com/v1/chat/completions",
        api_version: str = "v1"
    ):
        """
        Initialize the LLM API client.
        
        Args:
            base_url: Base URL for the API.
            api_version: API version to use.
        """
        self.base_url = base_url
        self.api_version = api_version
        self.headers = {
            "content-type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }

        # Check all envs have been set
        if not OPENAI_API_KEY:
            raise RuntimeError("Missing required environment variable. Please set OPENAI_API_KEY.")
        
        # Create a session with retry configuration
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            status_forcelist=[504, 502, 500],
            allowed_methods=["POST"],  # Only retry POST requests
            backoff_factor=0  # No backoff between retries
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
    
    def complete(
        self,
        prompt: str,
        model: str = "o1",
        reasoning_effort: str = "medium",
        max_tokens: int = 16384,
        temperature: float = 1,
        system: Optional[str] = None,
        stop_sequences: Optional[List[str]] = None,
        max_retries: int = 3,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a completion from the LLM.
        
        Args:
            prompt: The user prompt to send to the LLM
            model: Model to use (e.g., "claude-3-opus-20240229", "claude-3-sonnet-20240229")
            max_tokens: Maximum number of tokens to generate
            temperature: Sampling temperature (0-1)
            system: Optional system prompt to set context
            stop_sequences: Optional list of sequences that will stop generation
            max_retries: Maximum number of retry attempts for 504 errors (default: 3)
            **kwargs: Additional parameters to pass to the API
            
        Returns:
            API response as a dictionary
        """
        url = f"{self.base_url}"
        
        payload = {
            "model": model,
            "messages": [
                {"role": "developer", "content": system},
                {"role": "user", "content": prompt}
            ],
            "reasoning_effort": reasoning_effort,
            "temperature": temperature,
            "response_format": {"type": "json_object"}
        }
        
        logging.debug(f"Sending payload to LLM.")
        try:
            response = self.session.post(
                url, 
                headers=self.headers, 
                json=payload, 
                timeout=(30, 1200)  # 30s connect timeout, 1200s read timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logging.error(e.response.content)
            raise