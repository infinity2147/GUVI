"""
Agentic Honey-Pot v5.1 - Optimized Intelligent Brain
Single LLM call, better strategic prompting, focused intelligence extraction

Key Fixes:
1. Single LLM call (analysis + response in one)
2. Stronger strategic guidance to avoid repetitive questions
3. Explicit "what to ask" examples based on gaps
4. Faster response times
"""

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import List, Optional, Dict, Any, Union
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
from tenacity import retry, stop_after_attempt, wait_exponential
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import random

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

import os

API_KEY = os.getenv("API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not API_KEY or not OPENAI_API_KEY:
    raise ValueError("API_KEY and OPENAI_API_KEY must be set")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

MAX_MESSAGE_LENGTH = 5000
MAX_MESSAGES_PER_SESSION = 18
MIN_MESSAGES_FOR_TERMINATION = 6

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

# ============================================================================
# INTELLIGENCE TRACKER
# ============================================================================

class IntelligenceTracker:
    """Smart tracker for extracted intelligence"""
    
    def __init__(self):
        self.bank_accounts = set()
        self.upi_ids = set()
        self.phone_numbers = set()
        self.urls = set()
        self.email_addresses = set()
        self.keywords = set()
        self.questions_asked = []  # Track question types
        self.message_count = 0
        self.lock = threading.Lock()
    
    def extract_from_text(self, text: str):
        """Extract intelligence from text"""
        with self.lock:
            # Bank accounts
            accounts = re.findall(r'\b\d{9,18}\b', text)
            self.bank_accounts.update(accounts)
            
            # UPI IDs
            upi_ids = re.findall(r'\b[\w\.-]+@(?:paytm|phonepe|ybl|oksbi|okhdfcbank|okicici|okaxis|axl|ibl|pnb|boi)\b', text, re.IGNORECASE)
            self.upi_ids.update(upi_ids)
            
            # Phone numbers
            phones = re.findall(r'(?:\+91[\s-]?)?[6-9]\d{9}', text)
            self.phone_numbers.update(phones)
            
            # URLs
            urls = re.findall(r'(?:https?://|www\.)[^\s]+', text, re.IGNORECASE)
            self.urls.update(urls)
            
            # Email addresses
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
            self.email_addresses.update(emails)
            
            # Keywords
            scam_keywords = ['otp', 'pin', 'cvv', 'account', 'block', 'urgent', 'verify', 'suspend', 'fraud', 'transaction']
            for kw in scam_keywords:
                if kw in text.lower():
                    self.keywords.add(kw)
    
    def add_question_asked(self, question_type: str):
        """Track question types to avoid repetition"""
        with self.lock:
            self.questions_asked.append(question_type)
    
    def get_summary(self) -> str:
        """Get intelligence summary for LLM"""
        with self.lock:
            return f"""Extracted So Far:
• Phones: {len(self.phone_numbers)} {list(self.phone_numbers)[:2] if self.phone_numbers else '[]'}
• URLs: {len(self.urls)} {list(self.urls)[:2] if self.urls else '[]'}
• Emails: {len(self.email_addresses)} {list(self.email_addresses)[:2] if self.email_addresses else '[]'}
• UPI: {len(self.upi_ids)} {list(self.upi_ids)[:2] if self.upi_ids else '[]'}
• Banks: {len(self.bank_accounts)} {list(self.bank_accounts)[:2] if self.bank_accounts else '[]'}
Questions Asked: {self.questions_asked[-5:] if self.questions_asked else 'none'}
Message #{self.message_count}"""
    
    def get_missing_intel_priorities(self) -> List[str]:
        """What we need most urgently"""
        with self.lock:
            priorities = []
            if len(self.phone_numbers) == 0:
                priorities.append("CONTACT_PHONE")
            if len(self.urls) == 0:
                priorities.append("WEBSITE_URL")
            if len(self.email_addresses) == 0:
                priorities.append("EMAIL_ADDRESS")
            if len(self.upi_ids) == 0 and len(self.bank_accounts) == 0:
                priorities.append("PAYMENT_INFO")
            return priorities
    
    def get_intelligence_score(self) -> int:
        """Quality score"""
        with self.lock:
            return (
                len(self.phone_numbers) * 10 +
                len(self.urls) * 8 +
                len(self.email_addresses) * 7 +
                len(self.upi_ids) * 10 +
                len(self.bank_accounts) * 10
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """Export for callback"""
        with self.lock:
            return {
                'bankAccounts': list(self.bank_accounts),
                'upiIds': list(self.upi_ids),
                'phishingLinks': list(self.urls),
                'phoneNumbers': list(self.phone_numbers),
                'emailAddresses': list(self.email_addresses),
                'suspiciousKeywords': list(self.keywords),
                'messageCount': self.message_count,
                'intelligenceScore': self.get_intelligence_score()
            }

# Global session storage
session_trackers = defaultdict(IntelligenceTracker)
session_locks = defaultdict(threading.Lock)

# ============================================================================
# OPTIMIZED INTELLIGENT AGENT
# ============================================================================

class OptimizedHoneypotAgent:
    """Single-call LLM agent with strong strategic guidance"""
    
    def __init__(self, api_key: str):
        self.client = AsyncOpenAI(api_key=api_key)
        self.model = "gpt-4o-mini"
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=8)
    )
    async def generate_response(
        self,
        session_id: str,
        current_message: str,
        conversation_history: List[Message],
        tracker: IntelligenceTracker
    ) -> Dict[str, Any]:
        """Single LLM call for response generation"""
        
        # Build conversation context (last 6 messages)
        conv_text = ""
        for msg in conversation_history[-6:]:
            sender = "Scammer" if msg.sender != "bot" else "Me"
            conv_text += f"{sender}: {msg.text}\n"
        conv_text += f"Scammer: {current_message}"
        
        # Get intelligence summary
        intel_summary = tracker.get_summary()
        missing_priorities = tracker.get_missing_intel_priorities()
        
        # Get question examples based on what we need
        question_examples = self._get_question_examples(missing_priorities, tracker.message_count)
        
        # Build strategic prompt
        prompt = f"""You are a REAL PERSON (not AI) receiving a scam message. Respond naturally to extract information.

CONVERSATION:
{conv_text}

INTELLIGENCE STATUS:
{intel_summary}

🎯 TOP PRIORITY - GET THESE:
{chr(10).join(f'• {p}' for p in missing_priorities[:2]) if missing_priorities else '• Keep extracting more details'}

STRATEGIC GUIDANCE:
{self._get_strategic_guidance(tracker.message_count, missing_priorities)}

EXAMPLE QUESTIONS YOU SHOULD ASK:
{question_examples}

⚠️ CRITICAL RULES:
1. Ask ONE clear question that gets missing intelligence
2. DON'T ask "what do you mean?" or "can you explain?" - that wastes messages
3. DON'T repeat questions from this list: {', '.join(tracker.questions_asked[-5:])}
4. BE DIRECT: "what's your phone number?", "where's the website?", "what's the email?"
5. Sound human: use "ok", "wait", "uh", lowercase, typos
6. Keep it SHORT: 1-2 sentences max
7. If they gave contact info, CONFIRM it: "so your number is [number]?"

Respond with JSON:
{{
  "reply": "your natural response (1-2 sentences)",
  "question_type": "brief label of what you asked"
}}

Example GOOD responses:
- "ok whats ur official number i can call back?"
- "wait where should i go to fix this? any website?"
- "so ur email is [email]? should i send there?"
- "which account number do u need from me?"

Example BAD responses (DON'T do these):
- "uh what do you mean by that?" ❌
- "can you explain more?" ❌
- "this is confusing" ❌
"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=120,
                temperature=0.75,
                timeout=15.0,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            reply = result.get('reply', 'what?')
            
            # Add human touches
            reply = self._add_human_touches(reply)
            
            # Track question
            if result.get('question_type'):
                tracker.add_question_asked(result['question_type'])
            
            return {
                'reply': reply,
                'confidence': 0.8
            }
            
        except Exception as e:
            logger.error(f"LLM error: {e}")
            # Intelligent fallback based on what we need
            return {
                'reply': self._get_smart_fallback(missing_priorities, tracker.message_count),
                'confidence': 0.3
            }
    
    def _get_strategic_guidance(self, message_count: int, missing: List[str]) -> str:
        """Get strategic guidance based on message count and gaps"""
        
        if message_count <= 2:
            return "First messages: Ask who they are and for verification (phone/website)"
        
        elif message_count <= 5:
            if "CONTACT_PHONE" in missing:
                return "Priority: Get their phone number. Ask: 'what's your number so i can call back?'"
            elif "WEBSITE_URL" in missing:
                return "Priority: Get website/portal. Ask: 'where should i go to check this?'"
            else:
                return "Priority: Get email address. Ask: 'what's your email?'"
        
        elif message_count <= 10:
            if "EMAIL_ADDRESS" in missing:
                return "Priority: Get email. Ask: 'should i email someone about this?'"
            elif "PAYMENT_INFO" in missing:
                return "Priority: Get payment details. Ask: 'which upi id should i use?'"
            else:
                return "Confirm details: Repeat back their contact info to make them confirm"
        
        else:
            return "Final push: Confirm ALL contact details one more time before complying"
    
    def _get_question_examples(self, missing: List[str], message_count: int) -> str:
        """Get specific question examples based on what we need"""
        
        examples = []
        
        if "CONTACT_PHONE" in missing:
            examples.extend([
                '"whats ur number so i can call u back?"',
                '"can u give me ur official helpline number?"',
                '"wait which number r u calling from?"'
            ])
        
        if "WEBSITE_URL" in missing:
            examples.extend([
                '"is there a website i should go to?"',
                '"where do i check this? any portal?"',
                '"what link should i click?"'
            ])
        
        if "EMAIL_ADDRESS" in missing:
            examples.extend([
                '"whats ur email address?"',
                '"should i email someone? what email?"',
                '"where should i send documents?"'
            ])
        
        if "PAYMENT_INFO" in missing:
            examples.extend([
                '"which upi id should i send to?"',
                '"whats ur payment details?"',
                '"where do i transfer money?"'
            ])
        
        if not examples:
            examples = [
                '"just to confirm, ur number is [number]?"',
                '"and the website is [url]?"',
                '"should i do this right now or later?"'
            ]
        
        # Return 2-3 examples
        return "\n".join(examples[:3])
    
    def _add_human_touches(self, text: str) -> str:
        """Add realistic imperfections"""
        if not text:
            return text
        
        # Lowercase sometimes
        if random.random() < 0.25 and text[0].isupper():
            text = text[0].lower() + text[1:]
        
        # Simple typos
        if random.random() < 0.2:
            typos = {'please': 'pls', 'you': 'u', 'your': 'ur', 'okay': 'ok', 'are': 'r'}
            for formal, informal in typos.items():
                if formal in text.lower() and random.random() < 0.5:
                    text = re.sub(f'\\b{formal}\\b', informal, text, flags=re.IGNORECASE, count=1)
                    break
        
        # Remove punctuation sometimes
        if random.random() < 0.15:
            text = text.rstrip('.,!?')
        
        return text
    
    def _get_smart_fallback(self, missing: List[str], message_count: int) -> str:
        """Intelligent fallback based on what we need"""
        
        if "CONTACT_PHONE" in missing:
            return random.choice([
                "whats ur number?",
                "can i call u back? whats ur number",
                "give me ur contact number"
            ])
        
        if "WEBSITE_URL" in missing:
            return random.choice([
                "where should i go for this?",
                "is there a website?",
                "what link do i click"
            ])
        
        if "EMAIL_ADDRESS" in missing:
            return random.choice([
                "whats ur email?",
                "should i email someone?",
                "where do i send info"
            ])
        
        # Default
        return random.choice([
            "ok what do i do",
            "wait what",
            "huh?",
            "can u repeat that"
        ])

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

active_agents = {}

def should_terminate_session(tracker: IntelligenceTracker) -> bool:
    """Intelligent termination"""
    
    if tracker.message_count < MIN_MESSAGES_FOR_TERMINATION:
        return False
    
    if tracker.message_count >= MAX_MESSAGES_PER_SESSION:
        return True
    
    intel_score = tracker.get_intelligence_score()
    has_multiple = sum([
        len(tracker.phone_numbers) > 0,
        len(tracker.urls) > 0,
        len(tracker.email_addresses) > 0,
        len(tracker.upi_ids) > 0 or len(tracker.bank_accounts) > 0
    ])
    
    # Good stopping points
    if intel_score >= 30 and tracker.message_count >= 8:
        return True
    
    if has_multiple >= 3 and tracker.message_count >= 10:
        return True
    
    if intel_score >= 50:
        return True
    
    return False

async def send_final_callback(session_id: str, tracker: IntelligenceTracker) -> bool:
    """Send to GUVI"""
    try:
        intel_dict = tracker.to_dict()
        
        payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": intel_dict['messageCount'],
            "extractedIntelligence": {
                "bankAccounts": intel_dict['bankAccounts'],
                "upiIds": intel_dict['upiIds'],
                "phishingLinks": intel_dict['phishingLinks'],
                "phoneNumbers": intel_dict['phoneNumbers'],
                "suspiciousKeywords": intel_dict['suspiciousKeywords']
            },
            "agentNotes": f"Intelligent extraction: Score {intel_dict['intelligenceScore']}, {intel_dict['messageCount']} messages"
        }
        
        logger.info(f"📤 Callback: {session_id[:8]}... | Score: {intel_dict['intelligenceScore']}")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                success = response.status == 200
                logger.info(f"{'✅' if success else '❌'} Callback: {response.status}")
                return success
                
    except Exception as e:
        logger.error(f"❌ Callback error: {e}")
        return False

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Honeypot API v5.1 Optimized",
    version="5.1.0"
)

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
@limiter.limit("30/minute")
async def honeypot_endpoint(
    request: Request,
    honeypot_request: HoneypotRequest,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """Main endpoint"""
    
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        session_id = honeypot_request.sessionId or f"session-{int(datetime.utcnow().timestamp() * 1000)}"
        
        # Extract message
        current_message = ""
        if isinstance(honeypot_request.message, str):
            current_message = honeypot_request.message.strip()
        elif isinstance(honeypot_request.message, dict):
            current_message = (
                honeypot_request.message.get("text") or
                honeypot_request.message.get("message") or
                ""
            ).strip()
        
        if not current_message:
            return HoneypotResponse(status="error", reply="?", sessionId=session_id)
        
        # Parse history
        conversation_history = []
        if isinstance(honeypot_request.conversationHistory, list):
            for msg in honeypot_request.conversationHistory:
                try:
                    if isinstance(msg, dict):
                        conversation_history.append(Message(**msg))
                    elif isinstance(msg, Message):
                        conversation_history.append(msg)
                except:
                    continue
        
        # Get tracker
        tracker = session_trackers[session_id]
        tracker.message_count += 1
        
        # Extract intelligence
        tracker.extract_from_text(current_message)
        
        logger.info(f"📨 {session_id[:8]}... Msg#{tracker.message_count}: {current_message[:50]}...")
        
        # Check if scam
        scam_indicators = len(tracker.keywords)
        is_scam = scam_indicators >= 2 or tracker.message_count > 1
        
        if not is_scam:
            return HoneypotResponse(
                status="success",
                reply=random.choice(["who is this", "wrong number", "?"]),
                sessionId=session_id
            )
        
        # Initialize agent
        if session_id not in active_agents:
            active_agents[session_id] = OptimizedHoneypotAgent(OPENAI_API_KEY)
            logger.info(f"🎯 New scam: {session_id[:8]}...")
        
        agent = active_agents[session_id]
        
        # Generate response (single LLM call)
        result = await agent.generate_response(
            session_id,
            current_message,
            conversation_history,
            tracker
        )
        
        reply = result['reply']
        
        logger.info(f"💬 Reply: {reply}")
        logger.info(f"📊 Score: {tracker.get_intelligence_score()} | Need: {', '.join(tracker.get_missing_intel_priorities()[:2])}")
        
        # Check termination
        if should_terminate_session(tracker):
            logger.info(f"🏁 Done: {session_id[:8]}... ({tracker.message_count} msgs)")
            asyncio.create_task(send_final_callback(session_id, tracker))
        
        return HoneypotResponse(
            status="success",
            reply=reply,
            sessionId=session_id,
            metadata={
                "messageCount": tracker.message_count,
                "intelligenceScore": tracker.get_intelligence_score()
            }
        )
    
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        logger.error(traceback.format_exc())
        return HoneypotResponse(status="error", reply="what", sessionId=honeypot_request.sessionId or "unknown")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "5.1.0", "active_sessions": len(active_agents)}

@app.get("/")
async def root():
    return {
        "service": "Optimized Honeypot v5.1",
        "features": ["Single LLM call", "Strategic questions", "Fast response", "No redundancy"]
    }

if __name__ == "__main__":
    print("=" * 70)
    print("🧠 OPTIMIZED HONEYPOT v5.1")
    print("=" * 70)
    print("✅ Single LLM call per message (faster)")
    print("✅ Strategic question guidance")
    print("✅ No repetitive clarifying questions")
    print("✅ Direct intelligence extraction")
    print("=" * 70)
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")