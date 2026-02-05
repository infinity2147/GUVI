"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
Advanced AI-Powered Scam Detection System with Multi-Agent Architecture

REFACTORED VERSION - Production Ready
Author: Team Innovation
Hackathon: India AI Impact Buildathon
"""

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any, Union
from openai import OpenAI, AsyncOpenAI
from enum import Enum
import uvicorn
import asyncio
import aiohttp
import re
import json
from datetime import datetime, timedelta
import hashlib
import traceback
import logging
from collections import defaultdict
import threading
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import tiktoken

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

import os

# Secure API key loading with validation
API_KEY = os.getenv("API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not API_KEY:
    raise ValueError("API_KEY environment variable must be set")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY environment variable must be set")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Configuration constants
MAX_MESSAGE_LENGTH = 5000
MAX_CONVERSATION_HISTORY = 50
SESSION_TIMEOUT_HOURS = 24
MAX_SESSIONS_PER_IP = 10
MAX_MESSAGES_PER_SESSION = 20
SCAM_DETECTION_THRESHOLD = 30
HIGH_CONFIDENCE_THRESHOLD = 80

# ============================================================================
# ENUMS
# ============================================================================

class EngagementStage(Enum):
    """Engagement stages for progressive scammer interaction"""
    INITIAL_CONFUSION = "initial_confusion"
    CAUTIOUS_INTEREST = "cautious_interest"
    BUILDING_TRUST = "building_trust"
    INFORMATION_EXTRACTION = "information_extraction"
    FINAL_PUSH = "final_push"

class ScamType(Enum):
    """Types of scams detected"""
    BANK_FRAUD = "bank_fraud"
    UPI_FRAUD = "upi_fraud"
    PHISHING = "phishing"
    LOTTERY = "lottery"
    IMPERSONATION = "impersonation"
    OTP_FRAUD = "otp_fraud"
    UNKNOWN = "unknown"

# ============================================================================
# SESSION MANAGEMENT WITH THREAD SAFETY
# ============================================================================

class SessionData:
    """Thread-safe session data structure"""
    def __init__(self):
        self.bank_accounts = set()
        self.upi_ids = set()
        self.phishing_links = set()
        self.phone_numbers = set()
        self.suspicious_keywords = set()
        self.message_count = 0
        self.scam_score = 0.0
        self.scam_type = None
        self.tactics = set()
        self.agent_notes = []
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.lock = threading.Lock()

    def update_activity(self):
        """Update last activity timestamp"""
        with self.lock:
            self.last_activity = datetime.utcnow()

    def increment_messages(self):
        """Thread-safe message counter increment"""
        with self.lock:
            self.message_count += 1

    def update_scam_score(self, score: float):
        """Thread-safe scam score update"""
        with self.lock:
            self.scam_score = max(self.scam_score, score)

    def add_intelligence(self, intel: Dict[str, List[str]]):
        """Thread-safe intelligence addition"""
        with self.lock:
            self.bank_accounts.update(intel.get('bankAccounts', []))
            self.upi_ids.update(intel.get('upiIds', []))
            self.phishing_links.update(intel.get('phishingLinks', []))
            self.phone_numbers.update(intel.get('phoneNumbers', []))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        with self.lock:
            return {
                'bankAccounts': list(self.bank_accounts),
                'upiIds': list(self.upi_ids),
                'phishingLinks': list(self.phishing_links),
                'phoneNumbers': list(self.phone_numbers),
                'suspiciousKeywords': list(self.suspicious_keywords),
                'messageCount': self.message_count,
                'scamScore': self.scam_score,
                'scamType': self.scam_type,
                'tactics': list(self.tactics),
                'agentNotes': self.agent_notes.copy()
            }

# Global session storage
active_sessions = {}
session_data = defaultdict(SessionData)
session_locks = defaultdict(threading.Lock)

# ============================================================================
# DATA MODELS
# ============================================================================

class Message(BaseModel):
    """Message model with validation"""
    sender: str = "unknown"
    text: str = ""
    timestamp: Optional[str] = None

    @validator('text')
    def validate_text(cls, v):
        if len(v) > MAX_MESSAGE_LENGTH:
            raise ValueError(f"Message too long (max {MAX_MESSAGE_LENGTH} characters)")
        return v

class ConversationMetadata(BaseModel):
    """Metadata about the conversation"""
    channel: str = "SMS"
    language: str = "English"
    locale: str = "IN"

class HoneypotRequest(BaseModel):
    """Request model with validation"""
    sessionId: Optional[str] = None
    message: Union[str, Dict[str, Any], None] = None
    conversationHistory: Optional[List[Union[Message, Dict[str, Any]]]] = None
    metadata: Optional[ConversationMetadata] = None

    @validator('sessionId')
    def validate_session_id(cls, v):
        if v and not re.match(r'^[\w-]{1,100}$', v):
            raise ValueError("Invalid session ID format")
        return v

class HoneypotResponse(BaseModel):
    """Response model"""
    status: str
    reply: str
    sessionId: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def count_tokens(text: str, model: str = "gpt-4o-mini") -> int:
    """Count tokens in text for the given model"""
    try:
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(text))
    except Exception as e:
        logger.warning(f"Token counting failed: {e}")
        # Rough estimate: 1 token ≈ 4 characters
        return len(text) // 4

def truncate_conversation_history(
    messages: List[Message],
    max_tokens: int = 6000,
    model: str = "gpt-4o-mini"
) -> List[Message]:
    """Truncate conversation history to fit within token limit"""
    if not messages:
        return []
    
    total_tokens = 0
    truncated = []
    
    # Keep most recent messages
    for msg in reversed(messages):
        msg_tokens = count_tokens(msg.text, model)
        if total_tokens + msg_tokens > max_tokens:
            break
        truncated.insert(0, msg)
        total_tokens += msg_tokens
    
    return truncated

def sanitize_for_logging(text: str, max_length: int = 100) -> str:
    """Sanitize sensitive data for logging"""
    # Redact potential sensitive information
    text = re.sub(r'\b\d{9,18}\b', '[ACCOUNT_REDACTED]', text)
    text = re.sub(r'\b[\w\.-]+@[\w\.-]+\b', '[UPI_REDACTED]', text)
    text = re.sub(r'\b[6-9]\d{9}\b', '[PHONE_REDACTED]', text)
    
    if len(text) > max_length:
        text = text[:max_length] + "..."
    
    return text

# ============================================================================
# SCAM DETECTION ENGINE (ENHANCED)
# ============================================================================

class ScamDetector:
    """Advanced scam detection with improved pattern matching"""
    
    # Comprehensive scam patterns (from original code)
    URGENCY_PATTERNS = [
        r'\b(urgent|immediately|now|today|asap|hurry|quick|fast)\b',
        r'\b(expire|expiring|expired|deadline|limited time)\b',
        r'\b(last chance|final notice|act now)\b'
    ]
    
    THREAT_PATTERNS = [
        r'\b(block|blocked|suspend|suspended|deactivate|terminate|close)\b',
        r'\b(account|card|service|access).*\b(will be|has been|is being)\b',
        r'\b(legal action|arrest|police|court|fine|penalty)\b',
        r'\b(unauthorized|suspicious|fraudulent) (activity|transaction|login)\b'
    ]
    
    REQUEST_PATTERNS = [
        r'\b(verify|confirm|update|validate|authenticate)\b.*\b(account|details|information)\b',
        r'\b(share|provide|send|give).*\b(otp|pin|password|cvv|code)\b',
        r'\b(click|tap|visit|go to).*\b(link|url|website)\b',
        r'\b(upi|bank|card|account).*\b(number|id|details)\b'
    ]
    
    REWARD_PATTERNS = [
        r'\b(won|win|winner|prize|reward|gift|lottery)\b',
        r'\b(congratulations|selected|eligible)\b',
        r'\b(free|cashback|discount|offer|deal)\b.*\b(\d+%|\$|\₹)\b',
        r'\b(claim|redeem|collect).*\b(prize|reward|money|cash)\b'
    ]
    
    IMPERSONATION_PATTERNS = [
        r'\b(bank|sbi|hdfc|icici|axis|kotak|pnb|canara)\b',
        r'\b(paytm|phonepe|googlepay|bhim|amazon|flipkart)\b',
        r'\b(government|income tax|gst|aadhaar|pan)\b',
        r'\b(customer care|support|helpline|service)\b'
    ]
    
    SCAM_KEYWORDS = {
        ScamType.BANK_FRAUD: ['account', 'bank', 'card', 'kyc', 'verify', 'blocked'],
        ScamType.UPI_FRAUD: ['upi', 'payment', 'transfer', 'wallet', 'paytm', 'phonepe'],
        ScamType.PHISHING: ['link', 'click', 'url', 'website', 'portal', 'login'],
        ScamType.LOTTERY: ['won', 'prize', 'lottery', 'lucky', 'selected', 'winner'],
        ScamType.IMPERSONATION: ['officer', 'government', 'tax', 'police', 'authority'],
        ScamType.OTP_FRAUD: ['otp', 'code', 'pin', 'verification', 'authenticate']
    }
    
    @staticmethod
    def analyze_message(text: str) -> Dict[str, Any]:
        """Comprehensive scam analysis with improved scoring"""
        if not text or not isinstance(text, str):
            return {
                'scam_score': 0,
                'is_scam': False,
                'scam_type': ScamType.UNKNOWN,
                'urgency_score': 0,
                'threat_score': 0,
                'request_score': 0,
                'suspicious_keywords': [],
                'confidence': 0.0
            }
        
        text_lower = text.lower()
        
        # Pattern matching scores
        urgency_score = sum(1 for p in ScamDetector.URGENCY_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        threat_score = sum(1 for p in ScamDetector.THREAT_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        request_score = sum(1 for p in ScamDetector.REQUEST_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        reward_score = sum(1 for p in ScamDetector.REWARD_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        impersonation_score = sum(1 for p in ScamDetector.IMPERSONATION_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        
        # Calculate overall scam score (0-100)
        scam_score = min(100, (
            urgency_score * 15 +
            threat_score * 20 +
            request_score * 25 +
            reward_score * 15 +
            impersonation_score * 20
        ))
        
        # Identify scam type
        scam_type = ScamType.UNKNOWN
        max_keywords = 0
        for stype, keywords in ScamDetector.SCAM_KEYWORDS.items():
            count = sum(1 for kw in keywords if kw in text_lower)
            if count > max_keywords:
                max_keywords = count
                scam_type = stype
        
        # Extract suspicious keywords
        all_keywords = set()
        for keywords in ScamDetector.SCAM_KEYWORDS.values():
            all_keywords.update([kw for kw in keywords if kw in text_lower])
        
        # Calculate confidence based on multiple factors
        confidence = min(1.0, (scam_score / 100) * (1 + (max_keywords * 0.1)))
        
        return {
            'scam_score': scam_score,
            'is_scam': scam_score >= SCAM_DETECTION_THRESHOLD,
            'scam_type': scam_type,
            'urgency_score': urgency_score,
            'threat_score': threat_score,
            'request_score': request_score,
            'suspicious_keywords': list(all_keywords),
            'confidence': confidence
        }
    
    @staticmethod
    def extract_intelligence(text: str) -> Dict[str, List[str]]:
        """Extract actionable intelligence using improved patterns"""
        intelligence = {
            'bankAccounts': [],
            'upiIds': [],
            'phishingLinks': [],
            'phoneNumbers': []
        }
        
        if not text or not isinstance(text, str):
            return intelligence
        
        try:
            # Extract bank account numbers
            bank_patterns = [
                r'\b\d{9,18}\b',
                r'\b[A-Z]{4}\d{7,16}\b',
            ]
            for pattern in bank_patterns:
                matches = re.findall(pattern, text)
                intelligence['bankAccounts'].extend(matches)
            
            # Extract UPI IDs (more specific pattern)
            upi_pattern = r'\b[\w\.-]+@(?:paytm|phonepe|ybl|oksbi|okhdfcbank|okicici|okaxis)\b'
            intelligence['upiIds'] = re.findall(upi_pattern, text, re.IGNORECASE)
            
            # Extract URLs/links
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            short_url_pattern = r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co)/[\w]+'
            intelligence['phishingLinks'] = re.findall(url_pattern, text) + re.findall(short_url_pattern, text)
            
            # Extract phone numbers (Indian format)
            phone_patterns = [
                r'\+91[\s-]?\d{10}',
                r'\b[6-9]\d{9}\b',
                r'\b0\d{2,4}[\s-]?\d{6,8}\b'
            ]
            for pattern in phone_patterns:
                matches = re.findall(pattern, text)
                intelligence['phoneNumbers'].extend(matches)
        except Exception as e:
            logger.error(f"Error extracting intelligence: {e}")
        
        return intelligence

# ============================================================================
# AI AGENT SYSTEM (ENHANCED WITH OPENAI BEST PRACTICES)
# ============================================================================

class HoneypotAgent:
    """Enhanced AI agent with proper OpenAI usage"""
    
    def __init__(self, api_key: str):
        self.client = AsyncOpenAI(api_key=api_key)
        self.model = "gpt-4o-mini"
        self.response_cache = {}
    
    def get_cache_key(self, scam_type: ScamType, stage: EngagementStage, message_hash: str) -> str:
        """Generate cache key for response caching"""
        return hashlib.md5(
            f"{scam_type.value}_{stage.value}_{message_hash[:8]}".encode()
        ).hexdigest()
    
    def generate_persona(self, scam_type: ScamType) -> str:
        """Generate appropriate persona based on scam type"""
        personas = {
            ScamType.BANK_FRAUD: "elderly person, not very tech-savvy, worried about account",
            ScamType.UPI_FRAUD: "middle-aged user, occasional UPI user, cautious but curious",
            ScamType.PHISHING: "young professional, uses banking apps, somewhat trusting",
            ScamType.LOTTERY: "hopeful individual, excited about potential winnings",
            ScamType.IMPERSONATION: "concerned citizen, respectful of authority",
            ScamType.OTP_FRAUD: "regular user, familiar with OTPs but not security-aware"
        }
        return personas.get(scam_type, "average user, cautious but can be convinced")
    
    def determine_engagement_stage(self, message_count: int) -> EngagementStage:
        """Determine current engagement stage"""
        if message_count <= 2:
            return EngagementStage.INITIAL_CONFUSION
        elif message_count <= 5:
            return EngagementStage.CAUTIOUS_INTEREST
        elif message_count <= 10:
            return EngagementStage.BUILDING_TRUST
        elif message_count <= 15:
            return EngagementStage.INFORMATION_EXTRACTION
        else:
            return EngagementStage.FINAL_PUSH
    
    def get_stage_instructions(self, stage: EngagementStage) -> str:
        """Get stage-specific instructions"""
        instructions = {
            EngagementStage.INITIAL_CONFUSION: "Show confusion and ask why they're contacting you. Express mild concern.",
            EngagementStage.CAUTIOUS_INTEREST: "Show some interest but remain skeptical. Ask basic questions about the process.",
            EngagementStage.BUILDING_TRUST: "Show more trust. Ask about specific details, deadlines, or next steps.",
            EngagementStage.INFORMATION_EXTRACTION: "Ask for contact information, account details they need, or payment methods. Show willingness to comply.",
            EngagementStage.FINAL_PUSH: "Express readiness to proceed but need final confirmation of details, websites, or contact methods."
        }
        return instructions.get(stage, "Keep the conversation going naturally.")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((asyncio.TimeoutError, Exception))
    )
    async def call_openai_with_structured_output(
        self,
        messages: List[Dict[str, str]],
        functions: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """Call OpenAI with structured output and retry logic"""
        try:
            # Use structured outputs for consistent JSON responses
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=200,
                temperature=0.7,
                timeout=30.0,
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "honeypot_response",
                        "strict": True,
                        "schema": {
                            "type": "object",
                            "properties": {
                                "reply": {
                                    "type": "string",
                                    "description": "The human-like response to the scammer"
                                },
                                "extracted_info": {
                                    "type": "object",
                                    "properties": {
                                        "bank_accounts": {"type": "array", "items": {"type": "string"}},
                                        "upi_ids": {"type": "array", "items": {"type": "string"}},
                                        "phone_numbers": {"type": "array", "items": {"type": "string"}},
                                        "urls": {"type": "array", "items": {"type": "string"}}
                                    },
                                    "required": ["bank_accounts", "upi_ids", "phone_numbers", "urls"],
                                    "additionalProperties": False
                                },
                                "confidence": {
                                    "type": "number",
                                    "description": "Confidence in the response quality (0-1)"
                                }
                            },
                            "required": ["reply", "extracted_info", "confidence"],
                            "additionalProperties": False
                        }
                    }
                }
            )
            
            # Parse the JSON response
            result = json.loads(response.choices[0].message.content)
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return {
                "reply": "I'm sorry, could you repeat that?",
                "extracted_info": {"bank_accounts": [], "upi_ids": [], "phone_numbers": [], "urls": []},
                "confidence": 0.3
            }
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise
    
    async def engage(
        self,
        session_id: str,
        current_message: str,
        conversation_history: List[Message],
        scam_analysis: Dict[str, Any],
        metadata: Optional[ConversationMetadata]
    ) -> Dict[str, Any]:
        """Generate human-like response with intelligence extraction"""
        
        try:
            scam_type = scam_analysis.get('scam_type', ScamType.UNKNOWN)
            if not isinstance(scam_type, ScamType):
                scam_type = ScamType.UNKNOWN
            
            message_count = len(conversation_history) + 1
            engagement_stage = self.determine_engagement_stage(message_count)
            
            # Check cache
            message_hash = hashlib.md5(current_message.encode()).hexdigest()
            cache_key = self.get_cache_key(scam_type, engagement_stage, message_hash)
            
            if cache_key in self.response_cache:
                logger.info(f"Using cached response for session {session_id}")
                return self.response_cache[cache_key]
            
            # Truncate conversation history to fit token limits
            truncated_history = truncate_conversation_history(conversation_history, max_tokens=4000)
            
            # Build proper conversation messages for OpenAI
            messages = []
            
            # System message with persona
            persona = self.generate_persona(scam_type)
            stage_instructions = self.get_stage_instructions(engagement_stage)
            
            system_prompt = f"""You are an AI agent operating a honeypot to detect scammers.

PERSONA: You are a {persona}.

SCAM TYPE: {scam_type.value}
ENGAGEMENT STAGE: {engagement_stage.value}
MESSAGE COUNT: {message_count}

INSTRUCTIONS:
1. Stay in character - be believable and human-like
2. NEVER reveal you're an AI or detected the scam
3. Show appropriate emotions based on the stage
4. {stage_instructions}
5. Extract any sensitive information mentioned (bank accounts, UPI IDs, phone numbers, URLs)
6. Keep responses brief (1-3 sentences)
7. Use conversational language with natural imperfections

You must respond with valid JSON matching this schema:
{{
  "reply": "your human-like response",
  "extracted_info": {{
    "bank_accounts": [],
    "upi_ids": [],
    "phone_numbers": [],
    "urls": []
  }},
  "confidence": 0.8
}}"""

            messages.append({"role": "system", "content": system_prompt})
            
            # Add conversation history with proper roles
            for msg in truncated_history:
                role = "assistant" if msg.sender == "bot" else "user"
                messages.append({"role": role, "content": msg.text})
            
            # Add current message
            messages.append({"role": "user", "content": current_message})
            
            # Call OpenAI with structured output
            result = await self.call_openai_with_structured_output(messages)
            
            # Add human touches to the reply
            result['reply'] = self._add_human_touches(result['reply'], engagement_stage)
            
            # Cache the response
            self.response_cache[cache_key] = result
            
            # Limit cache size
            if len(self.response_cache) > 1000:
                # Remove oldest 200 entries
                keys_to_remove = list(self.response_cache.keys())[:200]
                for key in keys_to_remove:
                    del self.response_cache[key]
            
            return result
            
        except Exception as e:
            logger.error(f"Error in agent.engage: {e}")
            logger.error(traceback.format_exc())
            
            # Return safe fallback
            return {
                "reply": self._get_fallback_response(
                    self.determine_engagement_stage(len(conversation_history) + 1),
                    scam_analysis.get('scam_type', ScamType.UNKNOWN)
                ),
                "extracted_info": {"bank_accounts": [], "upi_ids": [], "phone_numbers": [], "urls": []},
                "confidence": 0.3
            }
    
    def _add_human_touches(self, text: str, stage: EngagementStage) -> str:
        """Add human-like imperfections to text"""
        import random
        
        if not text:
            return text
        
        # Add typos or informal language occasionally
        if random.random() < 0.25 and stage in [EngagementStage.INITIAL_CONFUSION, EngagementStage.CAUTIOUS_INTEREST]:
            replacements = {
                "okay": "ok",
                "yes": "yeah",
                "understand": "get it",
                "really": "rly"
            }
            for formal, informal in replacements.items():
                if formal in text.lower() and random.random() < 0.5:
                    text = re.sub(f"\\b{formal}\\b", informal, text, flags=re.IGNORECASE, count=1)
        
        # Add hesitation markers occasionally
        if random.random() < 0.15:
            hesitations = ["um, ", "uh, ", "well, ", "so "]
            text = random.choice(hesitations) + text[0].lower() + text[1:]
        
        return text
    
    def _get_fallback_response(self, stage: EngagementStage, scam_type: ScamType) -> str:
        """Fallback responses if AI generation fails"""
        fallbacks = {
            EngagementStage.INITIAL_CONFUSION: [
                "What is this about? I don't understand.",
                "Why are you messaging me?",
                "Is this really from my bank?"
            ],
            EngagementStage.CAUTIOUS_INTEREST: [
                "Can you explain more clearly?",
                "How do I know this is legitimate?",
                "What exactly do I need to do?"
            ],
            EngagementStage.BUILDING_TRUST: [
                "What happens next?",
                "Do I need to visit anywhere?",
                "Can you send me more details?"
            ],
            EngagementStage.INFORMATION_EXTRACTION: [
                "Where should I send the information?",
                "What's your official contact number?",
                "Is there a website I should use?"
            ],
            EngagementStage.FINAL_PUSH: [
                "Just to confirm, what details do you need?",
                "What's the process after I share info?",
                "Can I call your helpline to verify?"
            ]
        }
        
        import random
        return random.choice(fallbacks.get(stage, ["I see. Tell me more."]))

# ============================================================================
# SESSION MANAGEMENT FUNCTIONS
# ============================================================================

def update_session_intelligence(
    session_id: str,
    message: str,
    scam_analysis: Dict[str, Any],
    extracted_info: Optional[Dict[str, List[str]]] = None
):
    """Update intelligence gathered for this session (thread-safe)"""
    try:
        session = session_data[session_id]
        
        # Extract intelligence from message
        intel = ScamDetector.extract_intelligence(message)
        session.add_intelligence(intel)
        
        # Add extracted info from AI
        if extracted_info:
            session.add_intelligence({
                'bankAccounts': extracted_info.get('bank_accounts', []),
                'upiIds': extracted_info.get('upi_ids', []),
                'phoneNumbers': extracted_info.get('phone_numbers', []),
                'phishingLinks': extracted_info.get('urls', [])
            })
        
        # Update metadata
        session.increment_messages()
        session.update_scam_score(scam_analysis.get('scam_score', 0))
        session.update_activity()
        
        with session.lock:
            if scam_analysis.get('scam_type'):
                scam_type = scam_analysis['scam_type']
                if isinstance(scam_type, ScamType):
                    session.scam_type = scam_type.value
                else:
                    session.scam_type = str(scam_type)
            
            # Add suspicious keywords
            session.suspicious_keywords.update(scam_analysis.get('suspicious_keywords', []))
            
            # Track tactics
            if scam_analysis.get('urgency_score', 0) > 0:
                session.tactics.add('urgency_tactics')
            if scam_analysis.get('threat_score', 0) > 0:
                session.tactics.add('threat_based')
            if scam_analysis.get('request_score', 0) > 0:
                session.tactics.add('information_request')
                
    except Exception as e:
        logger.error(f"Error updating session intelligence: {e}")

def should_terminate_session(session_id: str) -> bool:
    """Determine if session should be terminated and reported"""
    try:
        session = session_data[session_id]
        
        with session.lock:
            # Terminate conditions
            if session.message_count >= MAX_MESSAGES_PER_SESSION:
                return True
            
            if session.scam_score >= HIGH_CONFIDENCE_THRESHOLD and session.message_count >= 5:
                return True
            
            if len(session.bank_accounts) > 0 or len(session.upi_ids) > 0:
                return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error checking session termination: {e}")
        return False

async def send_final_callback(session_id: str) -> bool:
    """Send final intelligence to GUVI endpoint (async with proper error handling)"""
    try:
        session = session_data[session_id]
        session_dict = session.to_dict()
        
        # Build agent notes
        notes_parts = []
        if session_dict.get('scamType'):
            notes_parts.append(f"Scam type: {session_dict['scamType']}")
        if session_dict.get('tactics'):
            notes_parts.append(f"Tactics: {', '.join(session_dict['tactics'])}")
        notes_parts.extend(session_dict.get('agentNotes', []))
        agent_notes = ". ".join(notes_parts) if notes_parts else "Scam engagement completed"
        
        payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": session_dict['messageCount'],
            "extractedIntelligence": {
                "bankAccounts": session_dict['bankAccounts'],
                "upiIds": session_dict['upiIds'],
                "phishingLinks": session_dict['phishingLinks'],
                "phoneNumbers": session_dict['phoneNumbers'],
                "suspiciousKeywords": session_dict['suspiciousKeywords']
            },
            "agentNotes": agent_notes
        }
        
        # Use aiohttp for async HTTP request
        async with aiohttp.ClientSession() as http_session:
            async with http_session.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                success = response.status == 200
                logger.info(f"{'✓' if success else '✗'} Callback for session {session_id}: {response.status}")
                return success
                
    except asyncio.TimeoutError:
        logger.error(f"✗ Callback timeout for session {session_id}")
        return False
    except Exception as e:
        logger.error(f"✗ Callback failed for session {session_id}: {e}")
        logger.error(traceback.format_exc())
        return False

async def cleanup_old_sessions():
    """Periodic cleanup of old sessions"""
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour
            
            current_time = datetime.utcnow()
            sessions_to_remove = []
            
            for session_id, session in session_data.items():
                with session.lock:
                    if (current_time - session.last_activity).total_seconds() > SESSION_TIMEOUT_HOURS * 3600:
                        sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                if session_id in active_sessions:
                    del active_sessions[session_id]
                if session_id in session_data:
                    del session_data[session_id]
                if session_id in session_locks:
                    del session_locks[session_id]
                logger.info(f"Cleaned up old session: {session_id}")
                
        except Exception as e:
            logger.error(f"Error in session cleanup: {e}")

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Agentic Honey-Pot API",
    description="Advanced AI-powered scam detection and intelligence extraction system",
    version="3.0.0"
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Start background tasks on application startup"""
    asyncio.create_task(cleanup_old_sessions())
    logger.info("🍯 Honeypot API started successfully")

@app.options("/honeypot")
async def honeypot_options():
    """Handle CORS preflight requests"""
    return {"status": "ok"}

@app.post("/honeypot", response_model=HoneypotResponse)
@limiter.limit("20/minute")
async def honeypot_endpoint(
    request: Request,
    honeypot_request: HoneypotRequest,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """Main honeypot endpoint for scam detection and engagement"""
    
    # Authentication
    if x_api_key != API_KEY:
        logger.warning(f"Invalid API key from {request.client.host}")
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        # Generate or validate session ID
        session_id = honeypot_request.sessionId or f"session-{int(datetime.utcnow().timestamp() * 1000)}"
        
        # Extract current message safely
        current_message = ""
        if isinstance(honeypot_request.message, str):
            current_message = honeypot_request.message.strip()
        elif isinstance(honeypot_request.message, dict):
            current_message = (
                honeypot_request.message.get("text") or
                honeypot_request.message.get("message") or
                honeypot_request.message.get("content") or
                ""
            ).strip()
        
        if not current_message:
            return HoneypotResponse(
                status="error",
                reply="I didn't receive any message. Could you try again?",
                sessionId=session_id
            )
        
        # Validate message length
        if len(current_message) > MAX_MESSAGE_LENGTH:
            raise HTTPException(
                status_code=400,
                detail=f"Message too long (max {MAX_MESSAGE_LENGTH} characters)"
            )
        
        # Parse conversation history
        conversation_history = []
        if isinstance(honeypot_request.conversationHistory, list):
            for msg in honeypot_request.conversationHistory[:MAX_CONVERSATION_HISTORY]:
                try:
                    if isinstance(msg, dict):
                        conversation_history.append(Message(**msg))
                    elif isinstance(msg, Message):
                        conversation_history.append(msg)
                except Exception as msg_err:
                    logger.warning(f"Could not parse message in history: {msg_err}")
                    continue
        
        # Log sanitized message
        logger.info(f"Session {session_id}: {sanitize_for_logging(current_message)}")
        
        # Analyze message for scam indicators
        scam_analysis = ScamDetector.analyze_message(current_message)
        
        # Check if this is a scam or ongoing engagement
        is_ongoing_scam = session_data[session_id].scam_score >= SCAM_DETECTION_THRESHOLD
        
        if scam_analysis['is_scam'] or is_ongoing_scam:
            # Initialize agent if needed
            if session_id not in active_sessions:
                active_sessions[session_id] = HoneypotAgent(OPENAI_API_KEY)
            
            agent = active_sessions[session_id]
            
            # Generate AI response with intelligence extraction
            result = await agent.engage(
                session_id=session_id,
                current_message=current_message,
                conversation_history=conversation_history,
                scam_analysis=scam_analysis,
                metadata=honeypot_request.metadata
            )
            
            reply = result.get('reply', 'I see. Could you explain more?')
            extracted_info = result.get('extracted_info', {})
            
            # Update session intelligence
            update_session_intelligence(
                session_id,
                current_message,
                scam_analysis,
                extracted_info
            )
            
            # Check if session should terminate
            if should_terminate_session(session_id):
                session_data[session_id].agent_notes.append(
                    f"Session terminated after {session_data[session_id].message_count} messages"
                )
                # Schedule async callback
                asyncio.create_task(send_final_callback(session_id))
                logger.info(f"Session {session_id} terminated, callback scheduled")
            
            return HoneypotResponse(
                status="success",
                reply=reply,
                sessionId=session_id,
                metadata={
                    "scamScore": scam_analysis['scam_score'],
                    "confidence": result.get('confidence', 0.5)
                }
            )
        
        else:
            # Not detected as scam - respond cautiously
            return HoneypotResponse(
                status="success",
                reply="I'm sorry, I don't understand. Who is this?",
                sessionId=session_id
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"ERROR in honeypot_endpoint: {e}")
        logger.error(traceback.format_exc())
        
        return HoneypotResponse(
            status="error",
            reply="I'm having trouble understanding. Could you repeat that?",
            sessionId=honeypot_request.sessionId or "unknown"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint with detailed status"""
    return {
        "status": "healthy",
        "version": "3.0.0",
        "active_sessions": len(active_sessions),
        "total_session_data": len(session_data),
        "timestamp": datetime.utcnow().isoformat(),
        "uptime_seconds": None  # Could track actual uptime
    }

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Agentic Honey-Pot API",
        "version": "3.0.0",
        "status": "active",
        "features": [
            "Advanced scam detection",
            "Multi-stage engagement",
            "Intelligence extraction",
            "Rate limiting",
            "Structured outputs"
        ],
        "endpoints": {
            "honeypot": "/honeypot (POST)",
            "health": "/health (GET)",
            "test": "/test (GET)",
            "docs": "/docs",
            "metrics": "/metrics (GET)"
        }
    }

@app.get("/test")
async def test_endpoint():
    """Test endpoint for connectivity"""
    return {
        "status": "success",
        "message": "Honeypot API is accessible",
        "timestamp": datetime.utcnow().isoformat(),
        "cors_enabled": True,
        "rate_limiting": True
    }

@app.get("/metrics")
async def metrics_endpoint(x_api_key: str = Header(..., alias="x-api-key")):
    """Get system metrics (requires authentication)"""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    total_messages = sum(s.message_count for s in session_data.values())
    total_bank_accounts = sum(len(s.bank_accounts) for s in session_data.values())
    total_upi_ids = sum(len(s.upi_ids) for s in session_data.values())
    
    scam_type_distribution = defaultdict(int)
    for session in session_data.values():
        if session.scam_type:
            scam_type_distribution[session.scam_type] += 1
    
    return {
        "active_sessions": len(active_sessions),
        "total_sessions": len(session_data),
        "total_messages_exchanged": total_messages,
        "intelligence_extracted": {
            "bank_accounts": total_bank_accounts,
            "upi_ids": total_upi_ids,
        },
        "scam_type_distribution": dict(scam_type_distribution),
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("🍯 AGENTIC HONEY-POT API v3.0.0")
    print("=" * 70)
    print(f"✓ OpenAI integration: Enhanced with structured outputs")
    print(f"✓ Rate limiting: Enabled")
    print(f"✓ Session management: Thread-safe with cleanup")
    print(f"✓ Intelligence extraction: AI-powered")
    print("=" * 70)
    print(f"📚 API Documentation: http://0.0.0.0:8000/docs")
    print(f"❤️  Health Check: http://0.0.0.0:8000/health")
    print(f"📊 Metrics: http://0.0.0.0:8000/metrics")
    print("=" * 70)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )