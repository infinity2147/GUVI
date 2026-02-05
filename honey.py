"""
Agentic Honey-Pot v5.0 - Intelligent LLM Brain
Strategic Intelligence Extraction with Minimal Redundancy

Key Improvements:
1. LLM analyzes conversation strategically before responding
2. Tracks what's been asked/extracted to avoid redundancy
3. Dynamic strategy based on scammer behavior
4. Natural progression without rigid stage rules
5. Terminates intelligently when maximum intel extracted
"""

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any, Union
from openai import AsyncOpenAI
from enum import Enum
import uvicorn
import asyncio
import aiohttp
import re
import json
from datetime import datetime
import hashlib
import traceback
import logging
from collections import defaultdict
import threading
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import random

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
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
MAX_MESSAGES_PER_SESSION = 20
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
    """Smart tracker that knows what we have and what we need"""
    
    def __init__(self):
        self.bank_accounts = set()
        self.upi_ids = set()
        self.phone_numbers = set()
        self.urls = set()
        self.email_addresses = set()
        self.keywords = set()
        self.tactics_observed = set()
        self.questions_asked = []  # Track what we've asked
        self.message_count = 0
        self.scam_confidence = 0
        self.lock = threading.Lock()
    
    def extract_from_text(self, text: str):
        """Extract intelligence from text"""
        with self.lock:
            # Bank accounts
            accounts = re.findall(r'\b\d{9,18}\b', text)
            self.bank_accounts.update(accounts)
            
            # UPI IDs
            upi_ids = re.findall(r'\b[\w\.-]+@(?:paytm|phonepe|ybl|oksbi|okhdfcbank|okicici|okaxis|axl|ibl)\b', text, re.IGNORECASE)
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
            scam_keywords = ['otp', 'pin', 'cvv', 'account', 'block', 'urgent', 'verify', 'suspend', 'fraud']
            for kw in scam_keywords:
                if kw in text.lower():
                    self.keywords.add(kw)
    
    def add_question_asked(self, question_type: str):
        """Track what we've asked to avoid repetition"""
        with self.lock:
            self.questions_asked.append(question_type)
    
    def has_asked(self, question_type: str) -> bool:
        """Check if we've already asked this"""
        with self.lock:
            return question_type in self.questions_asked
    
    def get_missing_intel(self) -> List[str]:
        """What intelligence are we still missing?"""
        with self.lock:
            missing = []
            if len(self.phone_numbers) == 0:
                missing.append("contact_phone")
            if len(self.urls) == 0:
                missing.append("website_url")
            if len(self.email_addresses) == 0:
                missing.append("email_address")
            if len(self.upi_ids) == 0 and len(self.bank_accounts) == 0:
                missing.append("financial_info")
            return missing
    
    def get_intelligence_score(self) -> int:
        """Calculate quality score"""
        with self.lock:
            score = (
                len(self.phone_numbers) * 10 +
                len(self.urls) * 8 +
                len(self.email_addresses) * 7 +
                len(self.upi_ids) * 10 +
                len(self.bank_accounts) * 10
            )
            return score
    
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
# INTELLIGENT LLM AGENT
# ============================================================================

class IntelligentHoneypotAgent:
    """LLM-powered strategic agent that thinks before responding"""
    
    def __init__(self, api_key: str):
        self.client = AsyncOpenAI(api_key=api_key)
        self.model = "gpt-4o-mini"
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((asyncio.TimeoutError, Exception))
    )
    async def analyze_and_respond(
        self,
        session_id: str,
        current_message: str,
        conversation_history: List[Message],
        tracker: IntelligenceTracker
    ) -> Dict[str, Any]:
        """Two-phase approach: Analyze then Respond"""
        
        # Phase 1: Strategic Analysis
        analysis = await self._analyze_conversation(
            current_message,
            conversation_history,
            tracker
        )
        
        # Phase 2: Generate Response
        response = await self._generate_strategic_response(
            current_message,
            conversation_history,
            tracker,
            analysis
        )
        
        return response
    
    async def _analyze_conversation(
        self,
        current_message: str,
        history: List[Message],
        tracker: IntelligenceTracker
    ) -> Dict[str, Any]:
        """Phase 1: LLM analyzes the conversation strategically"""
        
        # Build conversation context
        conv_text = "\n".join([
            f"{'Scammer' if msg.sender != 'bot' else 'Me'}: {msg.text}"
            for msg in history[-5:]  # Last 5 messages
        ])
        conv_text += f"\nScammer: {current_message}"
        
        # What we have so far
        intel_summary = f"""
Intelligence Extracted So Far:
- Phone Numbers: {len(tracker.phone_numbers)} ({', '.join(list(tracker.phone_numbers)[:3]) or 'none'})
- URLs: {len(tracker.urls)} ({', '.join(list(tracker.urls)[:2]) or 'none'})
- Email Addresses: {len(tracker.email_addresses)} ({', '.join(list(tracker.email_addresses)[:2]) or 'none'})
- UPI IDs: {len(tracker.upi_ids)} ({', '.join(list(tracker.upi_ids)[:2]) or 'none'})
- Bank Accounts: {len(tracker.bank_accounts)} ({', '.join(list(tracker.bank_accounts)[:2]) or 'none'})

Questions Already Asked: {', '.join(tracker.questions_asked[-5:]) or 'none yet'}
Message Count: {tracker.message_count}
"""
        
        analysis_prompt = f"""You are analyzing a scam conversation to extract maximum intelligence efficiently.

CONVERSATION SO FAR:
{conv_text}

{intel_summary}

Your task: Analyze this strategically and provide a JSON response with:

1. **scam_type**: What type of scam is this? (bank_fraud, upi_fraud, phishing, otp_fraud, lottery, impersonation)

2. **urgency_level**: How urgent/threatening is the scammer? (1-5, where 5 is extremely urgent)

3. **intelligence_gaps**: What critical information are we still missing? List the TOP 2 priorities.

4. **scammer_pattern**: What is the scammer trying to get me to do? (e.g., "send OTP", "click link", "call number")

5. **victim_emotion**: What emotion should the victim show now? (confused, worried, scared, compliant, skeptical)

6. **next_action**: What should the victim do next to extract more intel? Choose ONE:
   - "ask_for_verification" - Ask how to verify legitimacy (gets phone/website)
   - "express_concern" - Show worry but ask for clarification (keeps them talking)
   - "request_instructions" - Ask what exactly to do (gets process details)
   - "confirm_details" - Repeat back what they said to confirm (makes them repeat contact info)
   - "show_compliance" - Agree but fumble on details (gets them to explain more)

7. **avoid_repeating**: What question types have we already asked that we should NOT ask again?

Respond ONLY with valid JSON:
{{
  "scam_type": "...",
  "urgency_level": 3,
  "intelligence_gaps": ["...", "..."],
  "scammer_pattern": "...",
  "victim_emotion": "...",
  "next_action": "...",
  "avoid_repeating": ["..."]
}}"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": analysis_prompt}],
                max_tokens=300,
                temperature=0.3,  # Lower temperature for analysis
                timeout=20.0,
                response_format={"type": "json_object"}
            )
            
            analysis = json.loads(response.choices[0].message.content)
            return analysis
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            # Fallback analysis
            return {
                "scam_type": "unknown",
                "urgency_level": 3,
                "intelligence_gaps": ["contact_info", "website"],
                "scammer_pattern": "requesting sensitive info",
                "victim_emotion": "confused",
                "next_action": "ask_for_verification",
                "avoid_repeating": []
            }
    
    async def _generate_strategic_response(
        self,
        current_message: str,
        history: List[Message],
        tracker: IntelligenceTracker,
        analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Phase 2: Generate response based on strategic analysis"""
        
        # Build conversation for context
        conv_text = "\n".join([
            f"{'Scammer' if msg.sender != 'bot' else 'Me'}: {msg.text}"
            for msg in history[-8:]
        ])
        
        # Map next_action to specific tactics
        action_tactics = {
            "ask_for_verification": [
                "Can I call you back on an official number to verify?",
                "What's your employee ID or reference number?",
                "Is there a website where I can check this?",
                "How do I know this is really from [bank name]?"
            ],
            "express_concern": [
                "This is really worrying me. What exactly happened?",
                "I don't understand why this is happening. Can you explain?",
                "Are you sure about this? This seems strange.",
                "What should I do? I'm confused."
            ],
            "request_instructions": [
                "What exactly do I need to do?",
                "Where should I send this information?",
                "Do I need to go anywhere or click something?",
                "Walk me through the steps, I'm not good with this stuff."
            ],
            "confirm_details": [
                "Just to confirm, you said [repeat their claim]?",
                "So you're from [their claimed source]? What's your contact number?",
                "Let me make sure I understand - you need me to [action]?",
                "And your number is [number they mentioned]? Should I save it?"
            ],
            "show_compliance": [
                "Okay, I'll do it. But which number should I send to again?",
                "I'm ready to help. What's the email address?",
                "I'm opening my phone now. Where exactly do I go?",
                "Yes, I understand. But can you send me the link one more time?"
            ]
        }
        
        next_action = analysis.get('next_action', 'express_concern')
        example_tactics = action_tactics.get(next_action, action_tactics['express_concern'])
        
        # Emotion mapping
        emotion_traits = {
            "confused": "sound uncertain, ask clarifying questions",
            "worried": "express concern, seek reassurance",
            "scared": "show panic, want to act quickly but fumble",
            "compliant": "agree to help but need clear instructions",
            "skeptical": "questioning but can be convinced"
        }
        
        victim_emotion = analysis.get('victim_emotion', 'confused')
        emotion_guidance = emotion_traits.get(victim_emotion, "be natural")
        
        response_prompt = f"""You are a REAL PERSON (not a bot) receiving a scam message. You must respond naturally to extract information.

CONVERSATION:
{conv_text}
Scammer: {current_message}

ANALYSIS:
- Scam Type: {analysis.get('scam_type')}
- Your Emotion: {victim_emotion} ({emotion_guidance})
- Urgency Level: {analysis.get('urgency_level')}/5
- What Scammer Wants: {analysis.get('scammer_pattern')}

YOUR GOAL THIS MESSAGE:
Action: {next_action}
Example approaches: {'; '.join(example_tactics[:2])}

INTELLIGENCE GAPS (prioritize asking about these):
{', '.join(analysis.get('intelligence_gaps', ['contact info']))}

CRITICAL RULES:
1. Sound like a REAL CONFUSED PERSON - not an AI
2. Keep response SHORT (1-2 sentences max, sometimes just a few words)
3. Use informal language: "ok", "yeah", "wait", "uh", "huh?"
4. Make typos occasionally if panicked
5. DON'T repeat questions you've asked before
6. Extract info naturally - don't be obvious
7. NEVER say "I cannot assist" or sound like customer service

Things to AVOID repeating: {', '.join(analysis.get('avoid_repeating', []))}

Respond with JSON:
{{
  "reply": "your natural human response",
  "question_type_used": "brief label of what you asked about"
}}

Example good responses:
- "wait who is this??"
- "ok but can u give me ur number so i can call back"
- "im scared what do i do"
- "which website should i go to?"
- "so ur saying i need to send otp to where exactly?"
"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": response_prompt}],
                max_tokens=150,
                temperature=0.8,  # Higher for natural variation
                timeout=20.0,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # Add human imperfections
            reply = result.get('reply', 'what?')
            reply = self._add_human_touches(reply, analysis.get('urgency_level', 3))
            
            # Track what we asked
            if result.get('question_type_used'):
                tracker.add_question_asked(result['question_type_used'])
            
            return {
                'reply': reply,
                'analysis': analysis,
                'confidence': 0.8
            }
            
        except Exception as e:
            logger.error(f"Response generation error: {e}")
            # Fallback
            fallbacks = [
                "wait what?",
                "who is this?",
                "im confused",
                "what do u mean?",
                "can u explain?"
            ]
            return {
                'reply': random.choice(fallbacks),
                'analysis': analysis,
                'confidence': 0.3
            }
    
    def _add_human_touches(self, text: str, urgency: int) -> str:
        """Add realistic human imperfections"""
        if not text:
            return text
        
        # More imperfections with higher urgency
        imperfection_chance = min(0.4, urgency * 0.08)
        
        # Lowercase sometimes
        if random.random() < imperfection_chance and text[0].isupper():
            text = text[0].lower() + text[1:]
        
        # Remove punctuation sometimes
        if random.random() < imperfection_chance:
            text = text.rstrip('.,!?')
        
        # Add extra punctuation if urgent
        if urgency >= 4 and '?' in text and random.random() < 0.3:
            text = text.replace('?', '??')
        
        # Typos
        if random.random() < imperfection_chance * 0.5:
            typos = {
                'please': 'pls', 'okay': 'ok', 'you': 'u',
                'your': 'ur', 'what': 'wht', 'are': 'r'
            }
            for formal, informal in typos.items():
                if formal in text.lower() and random.random() < 0.5:
                    text = re.sub(f'\\b{formal}\\b', informal, text, flags=re.IGNORECASE, count=1)
                    break
        
        return text

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

active_agents = {}

def should_terminate_session(tracker: IntelligenceTracker) -> bool:
    """Intelligent termination decision"""
    
    # Don't terminate too early
    if tracker.message_count < MIN_MESSAGES_FOR_TERMINATION:
        return False
    
    # Maximum messages reached
    if tracker.message_count >= MAX_MESSAGES_PER_SESSION:
        return True
    
    # High-quality intelligence gathered
    intel_score = tracker.get_intelligence_score()
    has_multiple_types = (
        (len(tracker.phone_numbers) > 0) +
        (len(tracker.urls) > 0) +
        (len(tracker.email_addresses) > 0) +
        (len(tracker.upi_ids) > 0 or len(tracker.bank_accounts) > 0)
    )
    
    # Good stopping points
    if intel_score >= 30 and tracker.message_count >= 8:
        return True
    
    if has_multiple_types >= 3 and tracker.message_count >= 10:
        return True
    
    return False

async def send_final_callback(session_id: str, tracker: IntelligenceTracker) -> bool:
    """Send intelligence to GUVI"""
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
            "agentNotes": f"Intelligent extraction completed. Intelligence score: {intel_dict['intelligenceScore']}"
        }
        
        logger.info(f"📤 Callback: Session {session_id[:8]}... | Score: {intel_dict['intelligenceScore']} | Items: {len(intel_dict['phoneNumbers']) + len(intel_dict['upiIds']) + len(intel_dict['phishingLinks']) + len(intel_dict['bankAccounts'])}")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                success = response.status == 200
                logger.info(f"{'✅' if success else '❌'} Callback HTTP {response.status}")
                return success
                
    except Exception as e:
        logger.error(f"❌ Callback error: {e}")
        return False

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Intelligent Honeypot API v5.0",
    description="LLM-powered strategic scam intelligence extraction",
    version="5.0.0"
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
    """Main endpoint - intelligent honeypot"""
    
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
            return HoneypotResponse(
                status="error",
                reply="huh?",
                sessionId=session_id
            )
        
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
        
        # Extract intelligence from current message
        tracker.extract_from_text(current_message)
        
        logger.info(f"📨 Session {session_id[:8]}... Msg#{tracker.message_count}: {current_message[:60]}...")
        
        # Check if this looks like a scam
        scam_indicators = len(tracker.keywords)
        is_scam = scam_indicators >= 2 or tracker.message_count > 1
        
        if not is_scam:
            return HoneypotResponse(
                status="success",
                reply=random.choice(["who is this?", "wrong number", "?"]),
                sessionId=session_id
            )
        
        # Initialize agent
        if session_id not in active_agents:
            active_agents[session_id] = IntelligentHoneypotAgent(OPENAI_API_KEY)
            logger.info(f"🎯 New scam detected: {session_id[:8]}...")
        
        agent = active_agents[session_id]
        
        # Generate intelligent response
        result = await agent.analyze_and_respond(
            session_id,
            current_message,
            conversation_history,
            tracker
        )
        
        reply = result['reply']
        
        logger.info(f"💬 Response: {reply}")
        logger.info(f"📊 Intel Score: {tracker.get_intelligence_score()} | Missing: {', '.join(tracker.get_missing_intel())}")
        
        # Check termination
        if should_terminate_session(tracker):
            logger.info(f"🏁 Session {session_id[:8]}... complete after {tracker.message_count} messages")
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
        return HoneypotResponse(
            status="error",
            reply="what?",
            sessionId=honeypot_request.sessionId or "unknown"
        )

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "5.0.0",
        "mode": "INTELLIGENT",
        "active_sessions": len(active_agents)
    }

@app.get("/")
async def root():
    return {
        "service": "Intelligent Honeypot API v5.0",
        "features": [
            "LLM strategic analysis",
            "Zero redundancy",
            "Context-aware responses",
            "Efficient intelligence extraction"
        ]
    }

if __name__ == "__main__":
    print("=" * 80)
    print("🧠 INTELLIGENT HONEYPOT API v5.0")
    print("=" * 80)
    print("✅ LLM Brain: Analyzes before responding")
    print("✅ Strategic: Extracts intel efficiently")
    print("✅ Zero Redundancy: Tracks what's been asked")
    print("✅ Natural: Sounds completely human")
    print("=" * 80)
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")