"""
Autonomous Honeypot v6.1 - OPTIMIZED FOR PERFORMANCE
Key improvements:
1. Reduced LLM timeouts with faster fallbacks
2. Streamlined prompts for faster responses
3. Async optimizations
4. Better error handling for production
"""
from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union, Literal
from openai import AsyncOpenAI
import uvicorn
import asyncio
import aiohttp
import re
import json
from datetime import datetime
import traceback
import logging
from collections import defaultdict
import threading
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import random
from enum import Enum

# ============================================================================
# LOGGING
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION - OPTIMIZED
# ============================================================================
import os

API_KEY = os.getenv("API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not API_KEY or not OPENAI_API_KEY:
    raise ValueError("API_KEY and OPENAI_API_KEY must be set")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Conversation limits
MAX_MESSAGE_LENGTH = 5000
MAX_MESSAGES_PER_SESSION = 20
MIN_MESSAGES_FOR_TERMINATION = 5
OPTIMAL_MESSAGE_RANGE = (8, 15)

# LLM settings - OPTIMIZED
LLM_MODEL = "gpt-4o-mini"  # CHANGED: Faster, cheaper model
LLM_TIMEOUT = 8.0  # CHANGED: Reduced from 20s to 8s
LLM_MAX_TOKENS = 150  # CHANGED: Reduced from 200
LLM_TEMPERATURE = 0.7  # CHANGED: Slightly lower for consistency
MAX_RETRIES = 2  # CHANGED: Reduced from 3

# Intelligence thresholds
HIGH_VALUE_SCORE = 50
GOOD_SCORE = 30
MIN_CATEGORIES = 2

# ============================================================================
# ENUMS AND TYPES
# ============================================================================
class IntelType(str, Enum):
    PHONE = "phone"
    EMAIL = "email"
    URL = "url"
    UPI = "upi"
    BANK_ACCOUNT = "bank_account"
    KEYWORD = "keyword"

class AgentAction(str, Enum):
    ASK_CONTACT = "ask_contact"
    ASK_PAYMENT = "ask_payment"
    CONFIRM_INFO = "confirm_info"
    SHOW_COMPLIANCE = "show_compliance"
    EXPRESS_URGENCY = "express_urgency"
    END_CONVERSATION = "end_conversation"

class ConversationPhase(str, Enum):
    INITIAL = "initial"
    EXTRACTION = "extraction"
    CONFIRMATION = "confirmation"
    CLOSING = "closing"

# ============================================================================
# DATA MODELS
# ============================================================================
class Message(BaseModel):
    sender: str = "unknown"
    text: str = ""
    timestamp: Optional[str] = None

class ConversationMetadata(BaseModel):
    channel: str = "SMS"
    language: str = "English"
    locale: str = "IN"

class HoneypotRequest(BaseModel):
    sessionId: Optional[str] = None
    message: Union[str, Dict[str, Any], None] = None
    conversationHistory: Optional[List[Union[Message, Dict[str, Any]]]] = None
    metadata: Optional[ConversationMetadata] = None

class HoneypotResponse(BaseModel):
    status: str
    reply: str
    sessionId: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class AgentThought(BaseModel):
    scammer_intent: str
    next_priority: str
    strategy: str

class AgentResponse(BaseModel):
    thinking: AgentThought
    action: AgentAction
    reply: str
    confidence: float = Field(ge=0.0, le=1.0)

# ============================================================================
# INTELLIGENCE EXTRACTION
# ============================================================================
class IntelligenceExtractor:
    """Optimized pattern-based extraction"""
    
    @staticmethod
    def extract_phone_numbers(text: str) -> List[str]:
        patterns = [
            r'\+91[-\s]?[6-9]\d{9}',
            r'\b[6-9]\d{9}\b',
            r'1800[-\s]?\d{3}[-\s]?\d{3,4}',
        ]
        phones = set()
        for pattern in patterns:
            phones.update(re.findall(pattern, text))
        return list(phones)
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(pattern, text)))
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        patterns = [
            r'https?://[^\s]+',
            r'www\.[^\s]+',
            r'\b[a-z0-9-]+\.(com|net|org|in|co\.in)[^\s]*',
        ]
        urls = set()
        for pattern in patterns:
            urls.update(re.findall(pattern, text, re.IGNORECASE))
        return list(urls)
    
    @staticmethod
    def extract_upi_ids(text: str) -> List[str]:
        pattern = r'\b[\w\.-]+@(?:paytm|phonepe|ybl|oksbi|okhdfcbank|okicici|okaxis|axl|ibl|pnb|boi|airtel|freecharge|mobikwik)\b'
        return list(set(re.findall(pattern, text, re.IGNORECASE)))
    
    @staticmethod
    def extract_bank_accounts(text: str) -> List[str]:
        pattern = r'\b\d{9,18}\b'
        candidates = re.findall(pattern, text)
        accounts = [num for num in candidates if len(num) >= 11 and not num.startswith(('6', '7', '8', '9'))]
        return list(set(accounts))
    
    @staticmethod
    def extract_keywords(text: str) -> List[str]:
        keywords = [
            'otp', 'pin', 'cvv', 'password', 'account', 'block', 'blocked',
            'urgent', 'verify', 'verification', 'suspend', 'fraud', 'kyc'
        ]
        found = set()
        text_lower = text.lower()
        for keyword in keywords:
            if keyword in text_lower:
                found.add(keyword)
        return list(found)

# ============================================================================
# INTELLIGENCE TRACKER - SIMPLIFIED
# ============================================================================
class IntelligenceTracker:
    def __init__(self):
        self.phone_numbers = set()
        self.email_addresses = set()
        self.urls = set()
        self.upi_ids = set()
        self.bank_accounts = set()
        self.keywords = set()
        self.message_count = 0
        self.bot_replies = []
        self.scammer_messages = []
        self.actions_taken = []
        self.lock = threading.Lock()
        self.extractor = IntelligenceExtractor()
    
    def process_message(self, text: str, sender: str):
        with self.lock:
            if sender != "bot":
                self.scammer_messages.append(text)
                self.phone_numbers.update(self.extractor.extract_phone_numbers(text))
                self.email_addresses.update(self.extractor.extract_emails(text))
                self.urls.update(self.extractor.extract_urls(text))
                self.upi_ids.update(self.extractor.extract_upi_ids(text))
                self.bank_accounts.update(self.extractor.extract_bank_accounts(text))
                self.keywords.update(self.extractor.extract_keywords(text))
    
    def add_bot_reply(self, reply: str, action: AgentAction):
        with self.lock:
            self.bot_replies.append(reply)
            self.actions_taken.append(action.value)
            self.message_count += 1
    
    def get_intel_score(self) -> int:
        with self.lock:
            return int(
                len(self.phone_numbers) * 10 +
                len(self.email_addresses) * 8 +
                len(self.urls) * 8 +
                len(self.upi_ids) * 12 +
                len(self.bank_accounts) * 12
            )
    
    def get_missing_priorities(self) -> List[IntelType]:
        with self.lock:
            missing = []
            if not self.phone_numbers:
                missing.append(IntelType.PHONE)
            if not self.urls:
                missing.append(IntelType.URL)
            if not self.email_addresses:
                missing.append(IntelType.EMAIL)
            if not self.upi_ids and not self.bank_accounts:
                missing.append(IntelType.UPI)
            return missing
    
    def get_collected_categories(self) -> int:
        with self.lock:
            return sum([
                bool(self.phone_numbers),
                bool(self.email_addresses),
                bool(self.urls),
                bool(self.upi_ids or self.bank_accounts),
            ])
    
    def has_repeated_action(self, action: AgentAction, lookback: int = 3) -> bool:
        with self.lock:
            recent = self.actions_taken[-lookback:] if len(self.actions_taken) >= lookback else self.actions_taken
            return recent.count(action.value) > 1
    
    def get_compact_context(self) -> str:
        """OPTIMIZED: Shorter context for faster LLM processing"""
        with self.lock:
            return f"Phones:{len(self.phone_numbers)} Emails:{len(self.email_addresses)} URLs:{len(self.urls)} UPI:{len(self.upi_ids)} Banks:{len(self.bank_accounts)} Score:{self.get_intel_score()} Msg#{self.message_count}"
    
    def to_dict(self) -> Dict[str, Any]:
        with self.lock:
            return {
                'bankAccounts': list(self.bank_accounts),
                'upiIds': list(self.upi_ids),
                'phishingLinks': list(self.urls),
                'phoneNumbers': list(self.phone_numbers),
                'emailAddresses': list(self.email_addresses),
                'suspiciousKeywords': list(self.keywords),
                'messageCount': self.message_count,
                'intelligenceScore': self.get_intel_score()
            }

# ============================================================================
# AUTONOMOUS AGENT - OPTIMIZED
# ============================================================================
class AutonomousHoneypotAgent:
    """Optimized agent with faster responses"""
    
    def __init__(self, api_key: str):
        self.client = AsyncOpenAI(api_key=api_key)
        self.model = LLM_MODEL
    
    @retry(
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_exponential(multiplier=0.5, min=1, max=4),
        retry=retry_if_exception_type((asyncio.TimeoutError,))
    )
    async def generate_response(
        self,
        session_id: str,
        current_message: str,
        tracker: IntelligenceTracker
    ) -> AgentResponse:
        """OPTIMIZED: Faster LLM calls with streamlined prompts"""
        try:
            # Build COMPACT prompt
            prompt = self._build_compact_prompt(
                current_message=current_message,
                tracker=tracker
            )
            
            # Call LLM with timeout
            response = await asyncio.wait_for(
                self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self._get_system_prompt()},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=LLM_MAX_TOKENS,
                    temperature=LLM_TEMPERATURE,
                    response_format={"type": "json_object"}
                ),
                timeout=LLM_TIMEOUT
            )
            
            result = json.loads(response.choices[0].message.content)
            agent_response = self._parse_agent_response(result)
            agent_response.reply = self._humanize_text(agent_response.reply)
            
            # Quick self-correction check
            if tracker.has_repeated_action(agent_response.action, lookback=3):
                agent_response = self._quick_variation(tracker, agent_response)
            
            return agent_response
            
        except asyncio.TimeoutError:
            logger.warning(f"LLM timeout, using fast fallback")
            return self._fast_fallback(tracker, current_message)
        except Exception as e:
            logger.error(f"LLM error: {e}")
            return self._fast_fallback(tracker, current_message)
    
    def _get_system_prompt(self) -> str:
        """STREAMLINED system prompt"""
        return """You are a honeypot agent pretending to be a victim. Extract phone/email/URL/UPI from scammer.
Stay human: use casual language, typos, 1-2 sentences max.
Respond in JSON: {"thinking": {"scammer_intent": "...", "next_priority": "...", "strategy": "..."}, "action": "ask_contact|ask_payment|confirm_info|show_compliance|express_urgency", "reply": "...", "confidence": 0.8}"""
    
    def _build_compact_prompt(self, current_message: str, tracker: IntelligenceTracker) -> str:
        """OPTIMIZED: Much shorter prompt for faster processing"""
        missing = tracker.get_missing_priorities()
        recent_actions = tracker.actions_taken[-3:] if tracker.actions_taken else []
        
        return f"""Scammer: "{current_message}"

Status: {tracker.get_compact_context()}
Missing: {', '.join([m.value for m in missing]) if missing else 'All collected'}
Recent actions: {recent_actions}

What to do:
- If missing contact info → ask_contact ("whats ur number")
- If missing payment → ask_payment ("which upi")
- If info given → confirm_info ("so ur email is X?")
- Otherwise → show_compliance ("ok what do i do")

Reply as confused victim, 1-2 sentences, casual tone.
JSON response:"""
    
    def _parse_agent_response(self, result: Dict[str, Any]) -> AgentResponse:
        """Parse LLM response"""
        try:
            thinking_data = result.get('thinking', {})
            thinking = AgentThought(
                scammer_intent=thinking_data.get('scammer_intent', 'unknown'),
                next_priority=thinking_data.get('next_priority', 'contact'),
                strategy=thinking_data.get('strategy', 'extract info')
            )
            
            action = AgentAction(result.get('action', 'show_compliance'))
            reply = result.get('reply', 'what?').strip()
            confidence = float(result.get('confidence', 0.7))
            
            if len(reply) > 150:
                reply = reply[:147] + "..."
            
            return AgentResponse(
                thinking=thinking,
                action=action,
                reply=reply,
                confidence=max(0.0, min(1.0, confidence))
            )
        except Exception as e:
            logger.error(f"Parse error: {e}")
            return self._fast_fallback(None, "")
    
    def _quick_variation(self, tracker: IntelligenceTracker, original: AgentResponse) -> AgentResponse:
        """Fast variation without extra LLM call"""
        all_actions = list(AgentAction)
        recent = [AgentAction(a) for a in tracker.actions_taken[-3:]]
        available = [a for a in all_actions if a not in recent]
        
        if not available:
            available = [AgentAction.SHOW_COMPLIANCE, AgentAction.EXPRESS_URGENCY]
        
        new_action = random.choice(available)
        replies = {
            AgentAction.ASK_CONTACT: ["whats ur number", "can i call u"],
            AgentAction.ASK_PAYMENT: ["which upi", "what account"],
            AgentAction.SHOW_COMPLIANCE: ["ok what now", "tell me"],
            AgentAction.EXPRESS_URGENCY: ["is this urgent", "should i hurry"],
        }
        
        original.action = new_action
        original.reply = self._humanize_text(random.choice(replies.get(new_action, ["ok"])))
        original.confidence *= 0.8
        
        return original
    
    def _fast_fallback(self, tracker: Optional[IntelligenceTracker], msg: str) -> AgentResponse:
        """OPTIMIZED: Instant fallback without LLM"""
        if tracker:
            missing = tracker.get_missing_priorities()
            if IntelType.PHONE in missing:
                reply, action = "whats ur number", AgentAction.ASK_CONTACT
            elif IntelType.URL in missing:
                reply, action = "any website", AgentAction.ASK_CONTACT
            elif IntelType.UPI in missing:
                reply, action = "which upi id", AgentAction.ASK_PAYMENT
            else:
                reply, action = "ok what do i do", AgentAction.SHOW_COMPLIANCE
        else:
            reply, action = "what", AgentAction.SHOW_COMPLIANCE
        
        return AgentResponse(
            thinking=AgentThought(
                scammer_intent="fallback",
                next_priority="any",
                strategy="fallback"
            ),
            action=action,
            reply=self._humanize_text(reply),
            confidence=0.4
        )
    
    def _humanize_text(self, text: str) -> str:
        """Add human touches"""
        if random.random() < 0.3:
            text = text[0].lower() + text[1:] if text else text
        
        subs = {'please': 'pls', 'you': 'u', 'your': 'ur', 'okay': 'ok'}
        for formal, casual in subs.items():
            if formal in text.lower() and random.random() < 0.5:
                text = re.sub(formal, casual, text, flags=re.IGNORECASE, count=1)
                break
        
        if random.random() < 0.3 and text and text[-1] in '.!?':
            text = text[:-1]
        
        return text

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================
class SessionManager:
    def __init__(self):
        self.trackers: Dict[str, IntelligenceTracker] = defaultdict(IntelligenceTracker)
        self.agents: Dict[str, AutonomousHoneypotAgent] = {}
        self.lock = threading.Lock()
    
    def get_tracker(self, session_id: str) -> IntelligenceTracker:
        return self.trackers[session_id]
    
    def get_agent(self, session_id: str, api_key: str) -> AutonomousHoneypotAgent:
        with self.lock:
            if session_id not in self.agents:
                self.agents[session_id] = AutonomousHoneypotAgent(api_key)
            return self.agents[session_id]
    
    def should_terminate(self, tracker: IntelligenceTracker) -> tuple[bool, str]:
        if tracker.message_count < MIN_MESSAGES_FOR_TERMINATION:
            return False, ""
        if tracker.message_count >= MAX_MESSAGES_PER_SESSION:
            return True, "max_messages"
        
        score = tracker.get_intel_score()
        cats = tracker.get_collected_categories()
        
        if score >= HIGH_VALUE_SCORE:
            return True, f"high_value (score:{score})"
        if score >= GOOD_SCORE and tracker.message_count >= OPTIMAL_MESSAGE_RANGE[0]:
            return True, f"good_intel (score:{score})"
        if cats >= MIN_CATEGORIES + 1 and tracker.message_count >= OPTIMAL_MESSAGE_RANGE[0]:
            return True, f"multi_category ({cats}/4)"
        if tracker.message_count >= 15 and score < 25:
            return True, f"diminishing_returns"
        
        return False, ""
    
    def cleanup_session(self, session_id: str):
        with self.lock:
            if session_id in self.agents:
                del self.agents[session_id]

session_manager = SessionManager()

# ============================================================================
# CALLBACK - ASYNC BACKGROUND
# ============================================================================
async def send_final_callback(session_id: str, tracker: IntelligenceTracker, reason: str):
    """OPTIMIZED: Fire-and-forget callback"""
    try:
        intel = tracker.to_dict()
        payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": intel['messageCount'],
            "extractedIntelligence": {
                "bankAccounts": intel['bankAccounts'],
                "upiIds": intel['upiIds'],
                "phishingLinks": intel['phishingLinks'],
                "phoneNumbers": intel['phoneNumbers'],
                "emailAddresses": intel['emailAddresses'],
                "suspiciousKeywords": intel['suspiciousKeywords']
            },
            "agentNotes": f"v6.1 | Score:{intel['intelligenceScore']} | {reason}"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                GUVI_CALLBACK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    logger.info(f"✅ Callback success: {session_id[:8]}")
                else:
                    logger.error(f"❌ Callback failed: {response.status}")
    except Exception as e:
        logger.error(f"❌ Callback error: {e}")

# ============================================================================
# FASTAPI APP
# ============================================================================
app = FastAPI(title="Autonomous Honeypot v6.1 - Optimized", version="6.1.0")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.post("/honeypot", response_model=HoneypotResponse)
@limiter.limit("50/minute")
async def honeypot_endpoint(
    request: Request,
    honeypot_request: HoneypotRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """OPTIMIZED: Faster endpoint with background tasks"""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        # Session ID
        session_id = honeypot_request.sessionId or f"s-{int(datetime.utcnow().timestamp() * 1000)}"
        
        # Extract message
        current_message = ""
        if isinstance(honeypot_request.message, str):
            current_message = honeypot_request.message.strip()
        elif isinstance(honeypot_request.message, dict):
            current_message = (
                honeypot_request.message.get("text") or
                honeypot_request.message.get("message") or ""
            ).strip()
        
        if not current_message:
            return HoneypotResponse(
                status="error",
                reply="?",
                sessionId=session_id,
                metadata={"error": "empty_message"}
            )
        
        if len(current_message) > MAX_MESSAGE_LENGTH:
            current_message = current_message[:MAX_MESSAGE_LENGTH]
        
        # Get tracker
        tracker = session_manager.get_tracker(session_id)
        tracker.process_message(current_message, sender="scammer")
        
        # Simple first response
        if tracker.message_count == 0 and len(tracker.keywords) < 2:
            return HoneypotResponse(
                status="success",
                reply=random.choice(["who is this", "?", "what"]),
                sessionId=session_id,
                metadata={"messageCount": 0, "scamDetected": False}
            )
        
        # Get agent and generate response
        agent = session_manager.get_agent(session_id, OPENAI_API_KEY)
        agent_response = await agent.generate_response(session_id, current_message, tracker)
        
        tracker.add_bot_reply(agent_response.reply, agent_response.action)
        
        # Check termination
        should_end, reason = session_manager.should_terminate(tracker)
        
        if should_end:
            # Fire callback in background
            background_tasks.add_task(send_final_callback, session_id, tracker, reason)
            session_manager.cleanup_session(session_id)
        
        return HoneypotResponse(
            status="success",
            reply=agent_response.reply,
            sessionId=session_id,
            metadata={
                "messageCount": tracker.message_count,
                "intelligenceScore": tracker.get_intel_score(),
                "categories": tracker.get_collected_categories(),
                "action": agent_response.action.value,
                "terminated": should_end,
                "terminationReason": reason if should_end else None
            }
        )
    
    except Exception as e:
        logger.error(f"❌ Error: {e}\n{traceback.format_exc()}")
        return HoneypotResponse(
            status="error",
            reply="what",
            sessionId=honeypot_request.sessionId or "unknown",
            metadata={"error": str(e)}
        )

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": "6.1.0",
        "model": LLM_MODEL,
        "sessions": len(session_manager.agents)
    }

@app.get("/")
async def root():
    return {
        "service": "Autonomous Honeypot v6.1 - OPTIMIZED",
        "improvements": [
            "Faster LLM responses (8s timeout)",
            "Compact prompts for speed",
            "Background callback processing",
            "Better fallback handling",
            "Reduced token usage"
        ],
        "status": "operational"
    }

if __name__ == "__main__":
    print("🚀 Autonomous Honeypot v6.1 - OPTIMIZED FOR SPEED")
    print(f"⚡ Model: {LLM_MODEL} | Timeout: {LLM_TIMEOUT}s")
    print(f"🎯 Starting server...")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        timeout_keep_alive=25  # Keep-alive under 30s
    )