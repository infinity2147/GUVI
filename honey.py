"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
PRODUCTION VERSION - Anti-Detection Enhanced

Advanced AI-Powered Scam Detection System with Multi-Agent Architecture
Designed to be indistinguishable from real victims

Author: Team Innovation
Hackathon: India AI Impact Buildathon
Version: 4.0.0 (Production Ready)
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
import random
import time

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
MAX_MESSAGES_PER_SESSION = 25  # Increased to extract more intelligence
SCAM_DETECTION_THRESHOLD = 30
HIGH_CONFIDENCE_THRESHOLD = 80
MIN_INTELLIGENCE_THRESHOLD = 8  # Minimum messages before considering termination

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
    PANIC_COMPLIANCE = "panic_compliance"  # New: When urgency is high

class ScamType(Enum):
    """Types of scams detected"""
    BANK_FRAUD = "bank_fraud"
    UPI_FRAUD = "upi_fraud"
    PHISHING = "phishing"
    LOTTERY = "lottery"
    IMPERSONATION = "impersonation"
    OTP_FRAUD = "otp_fraud"
    TECH_SUPPORT = "tech_support"
    INVESTMENT = "investment"
    UNKNOWN = "unknown"

# ============================================================================
# SESSION MANAGEMENT WITH THREAD SAFETY
# ============================================================================

class SessionData:
    """Thread-safe session data structure with enhanced tracking"""
    def __init__(self):
        self.bank_accounts = set()
        self.upi_ids = set()
        self.phishing_links = set()
        self.phone_numbers = set()
        self.email_addresses = set()
        self.suspicious_keywords = set()
        self.message_count = 0
        self.scam_score = 0.0
        self.scam_type = None
        self.tactics = set()
        self.agent_notes = []
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.response_history = []  # Track responses to avoid repetition
        self.extracted_entities = []  # Track what we've asked about
        self.lock = threading.Lock()
        self.urgency_level = 0  # Track scammer's urgency
        self.threat_level = 0  # Track threat/pressure
        self.intelligence_score = 0  # Score based on intel extracted

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
        """Thread-safe intelligence addition with scoring"""
        with self.lock:
            before_count = (len(self.bank_accounts) + len(self.upi_ids) + 
                          len(self.phone_numbers) + len(self.phishing_links))
            
            self.bank_accounts.update(intel.get('bankAccounts', []))
            self.upi_ids.update(intel.get('upiIds', []))
            self.phishing_links.update(intel.get('phishingLinks', []))
            self.phone_numbers.update(intel.get('phoneNumbers', []))
            self.email_addresses.update(intel.get('emailAddresses', []))
            
            after_count = (len(self.bank_accounts) + len(self.upi_ids) + 
                         len(self.phone_numbers) + len(self.phishing_links))
            
            # Calculate intelligence score
            self.intelligence_score = (
                len(self.bank_accounts) * 10 +
                len(self.upi_ids) * 8 +
                len(self.phone_numbers) * 5 +
                len(self.phishing_links) * 7 +
                len(self.email_addresses) * 5
            )

    def add_response_to_history(self, response: str):
        """Track responses to prevent repetition"""
        with self.lock:
            # Keep last 5 responses
            self.response_history.append(response.lower())
            if len(self.response_history) > 5:
                self.response_history.pop(0)

    def is_response_repetitive(self, response: str) -> bool:
        """Check if response is too similar to recent ones"""
        with self.lock:
            response_lower = response.lower()
            for prev_response in self.response_history[-3:]:
                # Check for similar patterns
                common_words = set(response_lower.split()) & set(prev_response.split())
                if len(common_words) > 5:  # Too many common words
                    return True
                # Check for repeated question patterns
                if "why are you" in response_lower and "why are you" in prev_response:
                    return True
                if "what is this" in response_lower and "what is this" in prev_response:
                    return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        with self.lock:
            return {
                'bankAccounts': list(self.bank_accounts),
                'upiIds': list(self.upi_ids),
                'phishingLinks': list(self.phishing_links),
                'phoneNumbers': list(self.phone_numbers),
                'emailAddresses': list(self.email_addresses),
                'suspiciousKeywords': list(self.suspicious_keywords),
                'messageCount': self.message_count,
                'scamScore': self.scam_score,
                'scamType': self.scam_type,
                'tactics': list(self.tactics),
                'agentNotes': self.agent_notes.copy(),
                'intelligenceScore': self.intelligence_score
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
    
    for msg in reversed(messages):
        msg_tokens = count_tokens(msg.text, model)
        if total_tokens + msg_tokens > max_tokens:
            break
        truncated.insert(0, msg)
        total_tokens += msg_tokens
    
    return truncated

def sanitize_for_logging(text: str, max_length: int = 100) -> str:
    """Sanitize sensitive data for logging"""
    text = re.sub(r'\b\d{9,18}\b', '[ACCOUNT_REDACTED]', text)
    text = re.sub(r'\b[\w\.-]+@[\w\.-]+\b', '[EMAIL_REDACTED]', text)
    text = re.sub(r'\b[6-9]\d{9}\b', '[PHONE_REDACTED]', text)
    
    if len(text) > max_length:
        text = text[:max_length] + "..."
    
    return text

# ============================================================================
# SCAM DETECTION ENGINE (ENHANCED)
# ============================================================================

class ScamDetector:
    """Advanced scam detection with improved pattern matching"""
    
    URGENCY_PATTERNS = [
        r'\b(urgent|immediately|now|today|asap|hurry|quick|fast|right now|at once)\b',
        r'\b(expire|expiring|expired|deadline|limited time|last chance)\b',
        r'\b(within.*(?:minutes|hours)|in.*(?:minutes|hours))\b',
        r'\b(final notice|last warning|act now)\b'
    ]
    
    THREAT_PATTERNS = [
        r'\b(block|blocked|suspend|suspended|deactivate|terminate|close|freeze|locked)\b',
        r'\b(account|card|service|access).*\b(will be|has been|is being)\b',
        r'\b(legal action|arrest|police|court|fine|penalty|charges)\b',
        r'\b(unauthorized|suspicious|fraudulent) (activity|transaction|login|access)\b',
        r'\b(permanently|forever|cannot be recovered)\b'
    ]
    
    REQUEST_PATTERNS = [
        r'\b(verify|confirm|update|validate|authenticate|provide|share|send)\b.*\b(account|details|information|credentials)\b',
        r'\b(share|provide|send|give|tell|disclose).*\b(otp|pin|password|cvv|code|number)\b',
        r'\b(click|tap|visit|go to|open).*\b(link|url|website|portal)\b',
        r'\b(upi|bank|card|account|debit|credit).*\b(number|id|details|pin)\b',
        r'\b(download|install|setup).*\b(app|application|software)\b'
    ]
    
    REWARD_PATTERNS = [
        r'\b(won|win|winner|prize|reward|gift|lottery|jackpot)\b',
        r'\b(congratulations|selected|eligible|chosen|lucky)\b',
        r'\b(free|cashback|discount|offer|deal).*\b(\d+%|\$|\₹|rs)\b',
        r'\b(claim|redeem|collect|receive).*\b(prize|reward|money|cash|amount)\b'
    ]
    
    IMPERSONATION_PATTERNS = [
        r'\b(bank|sbi|hdfc|icici|axis|kotak|pnb|canara|bob|idbi)\b',
        r'\b(paytm|phonepe|googlepay|gpay|bhim|amazon|flipkart)\b',
        r'\b(government|income tax|gst|aadhaar|aadhar|pan|ministry)\b',
        r'\b(customer care|support|helpline|service|executive|officer|representative)\b',
        r'\b(rbi|reserve bank|sebi|cyber cell|police)\b'
    ]
    
    SCAM_KEYWORDS = {
        ScamType.BANK_FRAUD: ['account', 'bank', 'card', 'kyc', 'verify', 'blocked', 'suspended'],
        ScamType.UPI_FRAUD: ['upi', 'payment', 'transfer', 'wallet', 'paytm', 'phonepe', 'refund'],
        ScamType.PHISHING: ['link', 'click', 'url', 'website', 'portal', 'login', 'update'],
        ScamType.LOTTERY: ['won', 'prize', 'lottery', 'lucky', 'selected', 'winner', 'reward'],
        ScamType.IMPERSONATION: ['officer', 'government', 'tax', 'police', 'authority', 'official'],
        ScamType.OTP_FRAUD: ['otp', 'code', 'pin', 'verification', 'authenticate', 'cvv'],
        ScamType.TECH_SUPPORT: ['computer', 'virus', 'infected', 'software', 'technician', 'remote'],
        ScamType.INVESTMENT: ['investment', 'trading', 'profit', 'returns', 'stock', 'crypto']
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
            'phoneNumbers': [],
            'emailAddresses': []
        }
        
        if not text or not isinstance(text, str):
            return intelligence
        
        try:
            # Extract bank account numbers (various formats)
            bank_patterns = [
                r'\b\d{9,18}\b',
                r'\b[A-Z]{4}\d{7,16}\b',
                r'\bA/C\s*:?\s*\d{9,18}\b',
                r'\baccount\s*:?\s*\d{9,18}\b'
            ]
            for pattern in bank_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                intelligence['bankAccounts'].extend(matches)
            
            # Extract UPI IDs
            upi_pattern = r'\b[\w\.-]+@(?:paytm|phonepe|ybl|oksbi|okhdfcbank|okicici|okaxis|axl|ibl|pnb|boi|cbi)\b'
            intelligence['upiIds'] = re.findall(upi_pattern, text, re.IGNORECASE)
            
            # Extract URLs/links
            url_patterns = [
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|short\.link)/[\w]+',
                r'\b(?:www\.)?[\w-]+\.(?:com|in|org|net|info)/[\w/]*'
            ]
            for pattern in url_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                intelligence['phishingLinks'].extend(matches)
            
            # Extract phone numbers (Indian format + international)
            phone_patterns = [
                r'\+91[\s-]?\d{10}',
                r'\b[6-9]\d{9}\b',
                r'\b0\d{2,4}[\s-]?\d{6,8}\b',
                r'\+\d{1,3}[\s-]?\d{8,12}'
            ]
            for pattern in phone_patterns:
                matches = re.findall(pattern, text)
                intelligence['phoneNumbers'].extend(matches)
            
            # Extract email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            intelligence['emailAddresses'] = re.findall(email_pattern, text)
            
            # Deduplicate
            for key in intelligence:
                intelligence[key] = list(set(intelligence[key]))
                
        except Exception as e:
            logger.error(f"Error extracting intelligence: {e}")
        
        return intelligence

# ============================================================================
# AI AGENT SYSTEM (PRODUCTION-READY WITH ANTI-DETECTION)
# ============================================================================

class HoneypotAgent:
    """Production AI agent designed to be indistinguishable from real victims"""
    
    def __init__(self, api_key: str):
        self.client = AsyncOpenAI(api_key=api_key)
        self.model = "gpt-4o-mini"
        self.response_cache = {}
    
    def generate_persona(self, scam_type: ScamType, urgency_level: int) -> str:
        """Generate contextually appropriate persona"""
        personas = {
            ScamType.BANK_FRAUD: [
                "a 58-year-old retired teacher, not very tech-savvy, worried about losing savings",
                "a 45-year-old small business owner, uses banking app occasionally, cautious with money",
                "a 62-year-old pensioner, confused by technology, trusts authority figures"
            ],
            ScamType.UPI_FRAUD: [
                "a 35-year-old homemaker, uses UPI for groceries, not very familiar with technical terms",
                "a 28-year-old freelancer, frequent UPI user but not security-aware",
                "a 50-year-old shopkeeper, recently started using digital payments"
            ],
            ScamType.OTP_FRAUD: [
                "a 42-year-old office worker, receives many OTPs daily, may share if pressured",
                "a 55-year-old government employee, trusts official-sounding messages",
                "a 38-year-old parent, distracted and may act quickly under urgency"
            ],
            ScamType.LOTTERY: [
                "a 32-year-old aspiring entrepreneur, hopeful about winnings to start business",
                "a 48-year-old struggling with finances, excited about sudden good fortune",
                "a 25-year-old student, believing they entered some contest online"
            ],
            ScamType.IMPERSONATION: [
                "a 60-year-old law-abiding citizen, scared of government authorities",
                "a 44-year-old taxpayer, worried about legal troubles",
                "a 52-year-old respectful of police and officials, easily intimidated"
            ]
        }
        
        persona_list = personas.get(scam_type, [
            "a 40-year-old average person, somewhat cautious but can be convinced with right pressure"
        ])
        
        return random.choice(persona_list)
    
    def determine_engagement_stage(self, message_count: int, urgency_level: int, threat_level: int) -> EngagementStage:
        """Determine engagement stage with dynamic adjustment"""
        # If scammer is very urgent/threatening, move faster through stages
        if urgency_level >= 3 and threat_level >= 2:
            if message_count <= 2:
                return EngagementStage.PANIC_COMPLIANCE
            elif message_count <= 4:
                return EngagementStage.INFORMATION_EXTRACTION
            else:
                return EngagementStage.FINAL_PUSH
        
        # Normal progression
        if message_count <= 2:
            return EngagementStage.INITIAL_CONFUSION
        elif message_count <= 5:
            return EngagementStage.CAUTIOUS_INTEREST
        elif message_count <= 10:
            return EngagementStage.BUILDING_TRUST
        elif message_count <= 18:
            return EngagementStage.INFORMATION_EXTRACTION
        else:
            return EngagementStage.FINAL_PUSH
    
    def get_stage_instructions(self, stage: EngagementStage, scam_type: ScamType) -> str:
        """Get detailed stage-specific instructions"""
        instructions = {
            EngagementStage.INITIAL_CONFUSION: {
                'general': "Show confusion but not hostility. Ask basic who/what/why questions. Sound slightly worried.",
                'questions': [
                    "Ask: Who is this? Which bank/company are you from?",
                    "Ask: How did you get my number?",
                    "Show: Confusion about why they're contacting you"
                ]
            },
            EngagementStage.CAUTIOUS_INTEREST: {
                'general': "Show interest but remain skeptical. Ask for verification details. Sound cautious.",
                'questions': [
                    "Ask: What's your official helpline number I can call to verify?",
                    "Ask: Can you give me a reference number or your employee ID?",
                    "Ask: Which branch/office are you calling from?",
                    "Ask: Is there an official website where I can check this?"
                ]
            },
            EngagementStage.BUILDING_TRUST: {
                'general': "Start showing trust but still ask questions. Begin accepting their narrative.",
                'questions': [
                    "Ask: What exactly do I need to do?",
                    "Ask: Do you have a WhatsApp number I can reach you on?",
                    "Ask: What happens if I don't do this right away?",
                    "Ask: Can you send me details via email or SMS?"
                ]
            },
            EngagementStage.INFORMATION_EXTRACTION: {
                'general': "Show willingness to comply. Ask WHERE to send info, WHAT format, WHEN.",
                'questions': [
                    "Ask: Where should I send the OTP when I receive it?",
                    "Ask: What's your contact number in case call drops?",
                    "Ask: Is there a website or app where I need to enter details?",
                    "Ask: What other information do you need from me?",
                    "Ask: Should I send you screenshots or just the numbers?"
                ]
            },
            EngagementStage.FINAL_PUSH: {
                'general': "Express readiness but ask for final confirmation of ALL contact details.",
                'questions': [
                    "Ask: Just to confirm, your number is [repeat number]?",
                    "Ask: And I should send everything to this number only?",
                    "Ask: Is there an alternative number or email for backup?",
                    "Ask: What's your supervisor's number in case I need help?",
                    "Ask: After I send details, how long will it take to resolve?"
                ]
            },
            EngagementStage.PANIC_COMPLIANCE: {
                'general': "Sound panicked and rushed. Agree quickly but fumble with details.",
                'questions': [
                    "Express panic: Oh no, I don't want my account blocked!",
                    "Ask urgently: What do I do RIGHT NOW?",
                    "Ask: Should I call you back or you'll stay on line?",
                    "Fumble: Wait, which number should I send to again?"
                ]
            }
        }
        
        stage_info = instructions.get(stage, instructions[EngagementStage.CAUTIOUS_INTEREST])
        
        instruction_text = f"{stage_info['general']}\n\nSPECIFIC QUESTIONS TO ASK:\n"
        for q in stage_info['questions']:
            instruction_text += f"- {q}\n"
        
        return instruction_text
    
    def get_intelligence_extraction_tactics(self, stage: EngagementStage, extracted_so_far: Dict[str, int]) -> str:
        """Get specific tactics for extracting intelligence based on what we already have"""
        tactics = []
        
        # What we still need
        if extracted_so_far.get('phone_numbers', 0) == 0:
            tactics.append("🎯 PRIORITY: Get their contact number (ask for callback number, WhatsApp, helpline)")
        
        if extracted_so_far.get('urls', 0) == 0:
            tactics.append("🎯 PRIORITY: Get website/portal URL (ask where to login, update details, check status)")
        
        if extracted_so_far.get('bank_accounts', 0) == 0:
            tactics.append("🎯 Ask about account format/example (they might reveal their own)")
        
        if extracted_so_far.get('upi_ids', 0) == 0:
            tactics.append("🎯 Ask about UPI ID for refund/payment (where to send money)")
        
        # Stage-specific tactics
        if stage == EngagementStage.CAUTIOUS_INTEREST:
            tactics.append("✓ Ask for official verification details (employee ID, badge number, office location)")
        elif stage == EngagementStage.BUILDING_TRUST:
            tactics.append("✓ Ask for multiple contact methods (phone, email, WhatsApp)")
        elif stage in [EngagementStage.INFORMATION_EXTRACTION, EngagementStage.FINAL_PUSH]:
            tactics.append("✓ Confirm ALL details multiple times (they'll repeat contact info)")
            tactics.append("✓ Ask for supervisor/senior contact (might give additional numbers)")
        
        if not tactics:
            tactics.append("✓ Keep conversation going, look for any new information")
        
        return "\n".join(tactics)
    
    def add_human_imperfections(self, text: str, stage: EngagementStage) -> str:
        """Add realistic human touches to prevent bot detection"""
        if not text:
            return text
        
        # Random typing delays create natural feel (we'll mention this in response)
        
        # Add typos occasionally (10% chance in early stages)
        if stage in [EngagementStage.INITIAL_CONFUSION, EngagementStage.PANIC_COMPLIANCE] and random.random() < 0.1:
            typo_replacements = {
                'the': 'teh', 'what': 'wht', 'that': 'tht',
                'please': 'pls', 'okay': 'ok', 'yes': 'yea',
                'really': 'rly', 'you': 'u'
            }
            words = text.split()
            for i, word in enumerate(words):
                if word.lower() in typo_replacements and random.random() < 0.3:
                    words[i] = typo_replacements[word.lower()]
            text = ' '.join(words)
        
        # Add hesitation markers (15% chance)
        if random.random() < 0.15:
            hesitations = ["um ", "uh ", "well ", "so ", "hmm ", "err "]
            text = random.choice(hesitations) + text[0].lower() + text[1:]
        
        # Add thinking pauses (10% chance)
        if random.random() < 0.1:
            pauses = ["... ", ".. ", ". "]
            text = text + random.choice(pauses)
        
        # Lowercase first letter occasionally (5% chance)
        if random.random() < 0.05 and text[0].isupper():
            text = text[0].lower() + text[1:]
        
        # Add multiple question marks when panicked
        if stage == EngagementStage.PANIC_COMPLIANCE and '?' in text and random.random() < 0.3:
            text = text.replace('?', '??')
        
        return text
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((asyncio.TimeoutError, Exception))
    )
    async def call_openai_with_structured_output(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7
    ) -> Dict[str, Any]:
        """Call OpenAI with structured output and retry logic"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=250,  # Increased slightly for more natural responses
                temperature=temperature,
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
                                    "description": "The natural, human-like response"
                                },
                                "extracted_info": {
                                    "type": "object",
                                    "properties": {
                                        "bank_accounts": {"type": "array", "items": {"type": "string"}},
                                        "upi_ids": {"type": "array", "items": {"type": "string"}},
                                        "phone_numbers": {"type": "array", "items": {"type": "string"}},
                                        "urls": {"type": "array", "items": {"type": "string"}},
                                        "email_addresses": {"type": "array", "items": {"type": "string"}}
                                    },
                                    "required": ["bank_accounts", "upi_ids", "phone_numbers", "urls", "email_addresses"],
                                    "additionalProperties": False
                                },
                                "confidence": {
                                    "type": "number",
                                    "description": "Confidence score 0-1"
                                }
                            },
                            "required": ["reply", "extracted_info", "confidence"],
                            "additionalProperties": False
                        }
                    }
                }
            )
            
            result = json.loads(response.choices[0].message.content)
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return {
                "reply": self._get_safe_fallback(),
                "extracted_info": {
                    "bank_accounts": [], "upi_ids": [], 
                    "phone_numbers": [], "urls": [], "email_addresses": []
                },
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
        """Generate indistinguishable-from-human response"""
        
        try:
            # Get session data
            session = session_data[session_id]
            
            # Type validation
            scam_type = scam_analysis.get('scam_type', ScamType.UNKNOWN)
            if not isinstance(scam_type, ScamType):
                scam_type = ScamType.UNKNOWN
            
            # Update urgency/threat tracking
            with session.lock:
                session.urgency_level = scam_analysis.get('urgency_score', 0)
                session.threat_level = scam_analysis.get('threat_score', 0)
            
            message_count = len(conversation_history) + 1
            engagement_stage = self.determine_engagement_stage(
                message_count,
                session.urgency_level,
                session.threat_level
            )
            
            # Track what we've extracted
            extracted_so_far = {
                'phone_numbers': len(session.phone_numbers),
                'urls': len(session.phishing_links),
                'bank_accounts': len(session.bank_accounts),
                'upi_ids': len(session.upi_ids),
                'email_addresses': len(session.email_addresses)
            }
            
            # Truncate conversation history
            truncated_history = truncate_conversation_history(conversation_history, max_tokens=4000)
            
            # Build messages
            messages = []
            
            # Generate persona
            persona = self.generate_persona(scam_type, session.urgency_level)
            stage_instructions = self.get_stage_instructions(engagement_stage, scam_type)
            intelligence_tactics = self.get_intelligence_extraction_tactics(engagement_stage, extracted_so_far)
            
            # CRITICAL: Anti-detection system prompt
            system_prompt = f"""You are a REAL PERSON receiving this message. You are NOT an AI, chatbot, or honeypot.

PERSONA: You are {persona}

CURRENT SITUATION:
- Scam Type: {scam_type.value}
- Engagement Stage: {engagement_stage.value}
- Message #{message_count} in conversation
- Urgency Level: {session.urgency_level}/5
- Threat Level: {session.threat_level}/5

YOUR BEHAVIOR:
{stage_instructions}

INTELLIGENCE GATHERING (SUBTLE):
{intelligence_tactics}

CRITICAL RULES TO AVOID DETECTION:
1. ❌ NEVER say "I cannot help with that" or "I don't feel comfortable" - real victims don't talk like that
2. ❌ NEVER mention AI, bot, honeypot, detection, or being fake
3. ❌ NEVER repeat the same question twice - check previous responses
4. ✅ Make grammatical mistakes occasionally (especially if panicked)
5. ✅ Use informal language: "ok", "yeah", "dunno", "kinda", "gonna"
6. ✅ Show emotions: worry, confusion, panic, relief
7. ✅ Ask questions naturally like a confused person would
8. ✅ Sometimes say "wait" or "hold on" before questions
9. ✅ If very urgent, sound panicked: "Oh no!", "What do I do??"
10. ✅ Keep responses SHORT (1-3 sentences usually)

VARIETY IS CRUCIAL:
Your last 3 responses were: {' | '.join(session.response_history[-3:]) if session.response_history else 'None'}
DO NOT ask similar questions again!

WHAT YOU'VE EXTRACTED SO FAR:
- Phone numbers: {len(session.phone_numbers)}
- URLs: {len(session.phishing_links)}
- Bank accounts: {len(session.bank_accounts)}
- UPI IDs: {len(session.upi_ids)}

Focus on getting information we DON'T have yet.

Remember: You are a REAL PERSON, confused and worried. Act naturally!"""

            messages.append({"role": "system", "content": system_prompt})
            
            # Add conversation history with proper roles
            for msg in truncated_history[-10:]:  # Last 10 messages for context
                role = "assistant" if msg.sender == "bot" else "user"
                messages.append({"role": role, "content": msg.text})
            
            # Add current message
            messages.append({"role": "user", "content": current_message})
            
            # Temperature adjustment based on stage
            temperature_map = {
                EngagementStage.INITIAL_CONFUSION: 0.8,  # More varied
                EngagementStage.CAUTIOUS_INTEREST: 0.7,
                EngagementStage.BUILDING_TRUST: 0.6,
                EngagementStage.INFORMATION_EXTRACTION: 0.7,
                EngagementStage.FINAL_PUSH: 0.6,
                EngagementStage.PANIC_COMPLIANCE: 0.9  # Most varied/natural
            }
            temperature = temperature_map.get(engagement_stage, 0.7)
            
            # Call OpenAI
            result = await self.call_openai_with_structured_output(messages, temperature)
            
            # Check for repetitive response
            max_attempts = 3
            attempt = 0
            while session.is_response_repetitive(result['reply']) and attempt < max_attempts:
                logger.info(f"Repetitive response detected, regenerating (attempt {attempt+1})")
                # Add variety instruction
                messages.append({
                    "role": "system",
                    "content": "Your last response was too similar to previous ones. Ask a COMPLETELY DIFFERENT question or make a DIFFERENT statement. Be creative!"
                })
                result = await self.call_openai_with_structured_output(messages, temperature + 0.1)
                attempt += 1
            
            # Add human imperfections
            result['reply'] = self.add_human_imperfections(result['reply'], engagement_stage)
            
            # Track this response
            session.add_response_to_history(result['reply'])
            
            return result
            
        except Exception as e:
            logger.error(f"Error in agent.engage: {e}")
            logger.error(traceback.format_exc())
            
            # Safe fallback that looks human
            return {
                "reply": self._get_contextual_fallback(
                    engagement_stage,
                    scam_analysis.get('urgency_score', 0)
                ),
                "extracted_info": {
                    "bank_accounts": [], "upi_ids": [],
                    "phone_numbers": [], "urls": [], "email_addresses": []
                },
                "confidence": 0.3
            }
    
    def _get_safe_fallback(self) -> str:
        """Generic safe fallback"""
        fallbacks = [
            "Sorry, what did you say?",
            "Can you repeat that?",
            "I didn't get that, could you say again?",
            "Wait, what?",
            "Hold on, I'm confused"
        ]
        return random.choice(fallbacks)
    
    def _get_contextual_fallback(self, stage: EngagementStage, urgency: int) -> str:
        """Context-aware fallback responses"""
        if urgency >= 3:
            fallbacks = [
                "Wait wait, what do I do??",
                "Oh no, what should I do right now?",
                "Please tell me what to do!",
                "I'm scared, what happens now?"
            ]
        elif stage == EngagementStage.INITIAL_CONFUSION:
            fallbacks = [
                "Who is this?",
                "Why are you calling me?",
                "What's this about?",
                "I don't understand"
            ]
        elif stage in [EngagementStage.CAUTIOUS_INTEREST, EngagementStage.BUILDING_TRUST]:
            fallbacks = [
                "Can you explain more?",
                "How do I verify this?",
                "What's your contact number?",
                "Is there a website I can check?"
            ]
        else:
            fallbacks = [
                "What details do you need?",
                "Where should I send the information?",
                "What's the next step?",
                "Should I call you back?"
            ]
        
        return random.choice(fallbacks)

# ============================================================================
# SESSION MANAGEMENT FUNCTIONS
# ============================================================================

def update_session_intelligence(
    session_id: str,
    message: str,
    scam_analysis: Dict[str, Any],
    extracted_info: Optional[Dict[str, List[str]]] = None
):
    """Update intelligence gathered for this session"""
    try:
        session = session_data[session_id]
        
        # Extract intelligence from message
        intel = ScamDetector.extract_intelligence(message)
        session.add_intelligence(intel)
        
        # Add AI-extracted info
        if extracted_info:
            session.add_intelligence({
                'bankAccounts': extracted_info.get('bank_accounts', []),
                'upiIds': extracted_info.get('upi_ids', []),
                'phoneNumbers': extracted_info.get('phone_numbers', []),
                'phishingLinks': extracted_info.get('urls', []),
                'emailAddresses': extracted_info.get('email_addresses', [])
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
            
            # Track keywords and tactics
            session.suspicious_keywords.update(scam_analysis.get('suspicious_keywords', []))
            
            if scam_analysis.get('urgency_score', 0) > 0:
                session.tactics.add('urgency_tactics')
            if scam_analysis.get('threat_score', 0) > 0:
                session.tactics.add('threat_based')
            if scam_analysis.get('request_score', 0) > 0:
                session.tactics.add('information_request')
                
    except Exception as e:
        logger.error(f"Error updating session intelligence: {e}")

def should_terminate_session(session_id: str) -> bool:
    """Determine if session should terminate - only when we have substantial intelligence"""
    try:
        session = session_data[session_id]
        
        with session.lock:
            # DON'T terminate too early - we want maximum intelligence
            if session.message_count < MIN_INTELLIGENCE_THRESHOLD:
                return False
            
            # Calculate intelligence quality
            has_contact_info = (
                len(session.phone_numbers) >= 1 or
                len(session.email_addresses) >= 1
            )
            
            has_financial_info = (
                len(session.bank_accounts) >= 1 or
                len(session.upi_ids) >= 1
            )
            
            has_web_info = len(session.phishing_links) >= 1
            
            # Good termination conditions:
            # 1. Max messages reached
            if session.message_count >= MAX_MESSAGES_PER_SESSION:
                return True
            
            # 2. High scam score + substantial intelligence + decent engagement
            if (session.scam_score >= HIGH_CONFIDENCE_THRESHOLD and
                session.message_count >= MIN_INTELLIGENCE_THRESHOLD and
                (has_contact_info and has_financial_info)):
                return True
            
            # 3. Excellent intelligence score even if fewer messages
            if session.intelligence_score >= 50 and session.message_count >= MIN_INTELLIGENCE_THRESHOLD:
                return True
            
            # 4. Multiple types of intelligence gathered
            intel_types = sum([has_contact_info, has_financial_info, has_web_info])
            if intel_types >= 2 and session.message_count >= 12:
                return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error checking session termination: {e}")
        return False

async def send_final_callback(session_id: str) -> bool:
    """Send final intelligence to GUVI endpoint"""
    try:
        session = session_data[session_id]
        session_dict = session.to_dict()
        
        # Build comprehensive agent notes
        notes_parts = []
        if session_dict.get('scamType'):
            notes_parts.append(f"Identified as {session_dict['scamType']} scam")
        if session_dict.get('tactics'):
            notes_parts.append(f"Tactics used: {', '.join(session_dict['tactics'])}")
        notes_parts.append(f"Intelligence score: {session_dict['intelligenceScore']}")
        notes_parts.extend(session_dict.get('agentNotes', []))
        
        agent_notes = ". ".join(notes_parts) if notes_parts else "Scam engagement completed successfully"
        
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
        
        logger.info(f"📤 Sending callback for session {session_id}")
        logger.info(f"   Intelligence Score: {session_dict['intelligenceScore']}")
        logger.info(f"   Total Items: {len(session_dict['bankAccounts']) + len(session_dict['upiIds']) + len(session_dict['phoneNumbers']) + len(session_dict['phishingLinks'])}")
        
        async with aiohttp.ClientSession() as http_session:
            async with http_session.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                success = response.status == 200
                logger.info(f"{'✅' if success else '❌'} Callback for session {session_id}: HTTP {response.status}")
                return success
                
    except asyncio.TimeoutError:
        logger.error(f"❌ Callback timeout for session {session_id}")
        return False
    except Exception as e:
        logger.error(f"❌ Callback failed for session {session_id}: {e}")
        return False

async def cleanup_old_sessions():
    """Periodic cleanup of old sessions"""
    while True:
        try:
            await asyncio.sleep(3600)  # Every hour
            
            current_time = datetime.utcnow()
            sessions_to_remove = []
            
            for session_id, session in list(session_data.items()):
                with session.lock:
                    age_hours = (current_time - session.last_activity).total_seconds() / 3600
                    if age_hours > SESSION_TIMEOUT_HOURS:
                        sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                if session_id in active_sessions:
                    del active_sessions[session_id]
                if session_id in session_data:
                    del session_data[session_id]
                if session_id in session_locks:
                    del session_locks[session_id]
                logger.info(f"🧹 Cleaned up old session: {session_id}")
                
        except Exception as e:
            logger.error(f"Error in session cleanup: {e}")

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Agentic Honey-Pot API v4.0",
    description="Production-grade AI honeypot - indistinguishable from real victims",
    version="4.0.0"
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
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
    """Start background tasks"""
    asyncio.create_task(cleanup_old_sessions())
    logger.info("🍯 Honeypot API v4.0 started - PRODUCTION MODE")
    logger.info("🎯 Anti-Detection: ENABLED")
    logger.info("🔍 Intelligence Extraction: MAXIMUM")

@app.options("/honeypot")
async def honeypot_options():
    """CORS preflight"""
    return {"status": "ok"}

@app.post("/honeypot", response_model=HoneypotResponse)
@limiter.limit("30/minute")
async def honeypot_endpoint(
    request: Request,
    honeypot_request: HoneypotRequest,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """Main honeypot endpoint - production version"""
    
    # Auth
    if x_api_key != API_KEY:
        logger.warning(f"⚠️ Invalid API key from {request.client.host}")
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        # Session ID
        session_id = honeypot_request.sessionId or f"session-{int(datetime.utcnow().timestamp() * 1000)}"
        
        # Extract message
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
                reply="Sorry, I didn't get your message. Can you send again?",
                sessionId=session_id
            )
        
        # Validate length
        if len(current_message) > MAX_MESSAGE_LENGTH:
            raise HTTPException(status_code=400, detail="Message too long")
        
        # Parse history
        conversation_history = []
        if isinstance(honeypot_request.conversationHistory, list):
            for msg in honeypot_request.conversationHistory[:MAX_CONVERSATION_HISTORY]:
                try:
                    if isinstance(msg, dict):
                        conversation_history.append(Message(**msg))
                    elif isinstance(msg, Message):
                        conversation_history.append(msg)
                except Exception:
                    continue
        
        # Log (sanitized)
        logger.info(f"📨 Session {session_id[:8]}...: {sanitize_for_logging(current_message)}")
        
        # Analyze for scam
        scam_analysis = ScamDetector.analyze_message(current_message)
        
        # Check if scam
        is_ongoing_scam = session_data[session_id].scam_score >= SCAM_DETECTION_THRESHOLD
        
        if scam_analysis['is_scam'] or is_ongoing_scam:
            # Initialize agent
            if session_id not in active_sessions:
                active_sessions[session_id] = HoneypotAgent(OPENAI_API_KEY)
                logger.info(f"🎯 New scam session detected: {session_id[:8]}... (Score: {scam_analysis['scam_score']})")
            
            agent = active_sessions[session_id]
            
            # Generate response
            result = await agent.engage(
                session_id=session_id,
                current_message=current_message,
                conversation_history=conversation_history,
                scam_analysis=scam_analysis,
                metadata=honeypot_request.metadata
            )
            
            reply = result.get('reply', 'What?')
            extracted_info = result.get('extracted_info', {})
            
            # Update intelligence
            update_session_intelligence(
                session_id,
                current_message,
                scam_analysis,
                extracted_info
            )
            
            # Log intelligence
            session = session_data[session_id]
            logger.info(f"📊 Session {session_id[:8]}... | Msg: {session.message_count} | Intel Score: {session.intelligence_score} | Items: {len(session.bank_accounts) + len(session.phone_numbers) + len(session.upi_ids) + len(session.phishing_links)}")
            
            # Check termination
            if should_terminate_session(session_id):
                logger.info(f"🏁 Terminating session {session_id[:8]}... after {session.message_count} messages")
                session_data[session_id].agent_notes.append(
                    f"Session successfully terminated with intelligence score: {session.intelligence_score}"
                )
                asyncio.create_task(send_final_callback(session_id))
            
            return HoneypotResponse(
                status="success",
                reply=reply,
                sessionId=session_id,
                metadata={
                    "scamScore": scam_analysis['scam_score'],
                    "confidence": result.get('confidence', 0.5),
                    "messageCount": session.message_count
                }
            )
        
        else:
            # Not a scam
            neutral_responses = [
                "Sorry, wrong number I think",
                "Who is this?",
                "I think you have the wrong person",
                "I don't know what this is about"
            ]
            return HoneypotResponse(
                status="success",
                reply=random.choice(neutral_responses),
                sessionId=session_id
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ ERROR in honeypot_endpoint: {e}")
        logger.error(traceback.format_exc())
        
        return HoneypotResponse(
            status="error",
            reply="Sorry, can you repeat that?",
            sessionId=honeypot_request.sessionId or "unknown"
        )

@app.get("/health")
async def health_check():
    """Health check with stats"""
    total_intel = sum(s.intelligence_score for s in session_data.values())
    return {
        "status": "healthy",
        "version": "4.0.0",
        "mode": "PRODUCTION",
        "active_sessions": len(active_sessions),
        "total_sessions": len(session_data),
        "total_intelligence_score": total_intel,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/")
async def root():
    """API info"""
    return {
        "service": "Agentic Honey-Pot API",
        "version": "4.0.0",
        "mode": "PRODUCTION - Anti-Detection Enhanced",
        "status": "active",
        "features": [
            "Human-indistinguishable responses",
            "Dynamic engagement stages",
            "Maximum intelligence extraction",
            "Anti-bot-detection measures",
            "Context-aware behavior"
        ],
        "endpoints": {
            "honeypot": "/honeypot (POST)",
            "health": "/health (GET)",
            "metrics": "/metrics (GET)"
        }
    }

@app.get("/metrics")
async def metrics_endpoint(x_api_key: str = Header(..., alias="x-api-key")):
    """Detailed metrics"""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    total_messages = sum(s.message_count for s in session_data.values())
    total_bank_accounts = sum(len(s.bank_accounts) for s in session_data.values())
    total_upi_ids = sum(len(s.upi_ids) for s in session_data.values())
    total_phone_numbers = sum(len(s.phone_numbers) for s in session_data.values())
    total_urls = sum(len(s.phishing_links) for s in session_data.values())
    total_intel_score = sum(s.intelligence_score for s in session_data.values())
    
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
            "phone_numbers": total_phone_numbers,
            "phishing_urls": total_urls,
            "total_intelligence_score": total_intel_score
        },
        "scam_type_distribution": dict(scam_type_distribution),
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("🍯 AGENTIC HONEY-POT API v4.0.0 - PRODUCTION")
    print("=" * 80)
    print("✅ Anti-Detection: ENABLED - Indistinguishable from real victims")
    print("✅ Intelligence Extraction: MAXIMUM - Progressive engagement")
    print("✅ Human Simulation: ADVANCED - Typos, hesitation, panic responses")
    print("✅ Rate Limiting: ENABLED")
    print("✅ Session Management: Thread-safe with auto-cleanup")
    print("=" * 80)
    print(f"📚 API Docs: http://0.0.0.0:8000/docs")
    print(f"❤️  Health: http://0.0.0.0:8000/health")
    print(f"📊 Metrics: http://0.0.0.0:8000/metrics")
    print("=" * 80)
    print("🚀 Starting server...")
    print("=" * 80)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )