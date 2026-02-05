"""
Autonomous Honeypot v6.0 - LLM-Brain Powered Intelligence Extraction
Full autonomy, tool-based architecture, robust reasoning

Key Improvements:
1. LLM decides strategy dynamically (no hardcoded flowcharts)
2. Tool-based approach for actions
3. Self-correcting reasoning loop
4. Robust error handling and fallbacks
5. Memory of conversation context
6. Adaptive termination based on quality, not just count
"""

from fastapi import FastAPI, HTTPException, Header, Request
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
# CONFIGURATION
# ============================================================================

import os

API_KEY = os.getenv("API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not API_KEY or not OPENAI_API_KEY:
    raise ValueError("API_KEY and OPENAI_API_KEY must be set in environment variables")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Conversation limits
MAX_MESSAGE_LENGTH = 5000
MAX_MESSAGES_PER_SESSION = 20
MIN_MESSAGES_FOR_TERMINATION = 5
OPTIMAL_MESSAGE_RANGE = (8, 15)

# LLM settings
LLM_MODEL = "gpt-4o-mini"
LLM_TIMEOUT = 20.0
LLM_MAX_TOKENS = 200
LLM_TEMPERATURE = 0.8

# Intelligence thresholds
HIGH_VALUE_SCORE = 50
GOOD_SCORE = 30
MIN_CATEGORIES = 2

# ============================================================================
# ENUMS AND TYPES
# ============================================================================

class IntelType(str, Enum):
    """Types of intelligence we extract"""
    PHONE = "phone"
    EMAIL = "email"
    URL = "url"
    UPI = "upi"
    BANK_ACCOUNT = "bank_account"
    KEYWORD = "keyword"

class AgentAction(str, Enum):
    """Actions the agent can take"""
    ASK_CONTACT = "ask_contact"
    ASK_PAYMENT = "ask_payment"
    CONFIRM_INFO = "confirm_info"
    SHOW_COMPLIANCE = "show_compliance"
    EXPRESS_URGENCY = "express_urgency"
    END_CONVERSATION = "end_conversation"

class ConversationPhase(str, Enum):
    """Conversation phases"""
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
    """Agent's reasoning process"""
    scammer_intent: str = Field(description="What is the scammer trying to do?")
    information_revealed: List[str] = Field(description="What info did scammer reveal?")
    next_priority: str = Field(description="What intel to extract next?")
    victim_emotion: str = Field(description="What emotion should victim show?")
    strategy: str = Field(description="Overall strategy for this response")
    
class AgentResponse(BaseModel):
    """Agent's complete response"""
    thinking: AgentThought
    action: AgentAction
    reply: str
    confidence: float = Field(ge=0.0, le=1.0)

# ============================================================================
# INTELLIGENCE EXTRACTION & TRACKING
# ============================================================================

class IntelligenceExtractor:
    """Robust pattern-based intelligence extraction"""
    
    @staticmethod
    def extract_phone_numbers(text: str) -> List[str]:
        """Extract phone numbers with various formats"""
        patterns = [
            r'\+91[-\s]?[6-9]\d{9}',  # +91 format
            r'\b[6-9]\d{9}\b',  # 10 digit
            r'1800[-\s]?\d{3}[-\s]?\d{3,4}',  # Toll-free
            r'\d{3}[-\s]\d{3}[-\s]\d{4}',  # With dashes
        ]
        phones = set()
        for pattern in patterns:
            phones.update(re.findall(pattern, text))
        return list(phones)
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses"""
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(pattern, text)))
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs and domains"""
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
        """Extract UPI IDs"""
        pattern = r'\b[\w\.-]+@(?:paytm|phonepe|ybl|oksbi|okhdfcbank|okicici|okaxis|axl|ibl|pnb|boi|airtel|freecharge|mobikwik)\b'
        return list(set(re.findall(pattern, text, re.IGNORECASE)))
    
    @staticmethod
    def extract_bank_accounts(text: str) -> List[str]:
        """Extract potential bank account numbers"""
        # Look for 9-18 digit numbers that aren't phone numbers
        pattern = r'\b\d{9,18}\b'
        candidates = re.findall(pattern, text)
        # Filter out phone numbers
        accounts = []
        for num in candidates:
            if len(num) >= 11 and not num.startswith(('6', '7', '8', '9')):
                accounts.append(num)
        return list(set(accounts))
    
    @staticmethod
    def extract_keywords(text: str) -> List[str]:
        """Extract scam-related keywords"""
        scam_keywords = [
            'otp', 'pin', 'cvv', 'password', 'account', 'block', 'blocked',
            'urgent', 'immediately', 'verify', 'verification', 'suspend', 'suspended',
            'fraud', 'fraudulent', 'transaction', 'unauthorized', 'expire', 'expired',
            'confirm', 'update', 'secure', 'security', 'kyc', 'aadhar', 'pan'
        ]
        found = set()
        text_lower = text.lower()
        for keyword in scam_keywords:
            if keyword in text_lower:
                found.add(keyword)
        return list(found)

class IntelligenceTracker:
    """Thread-safe tracker for extracted intelligence with quality metrics"""
    
    def __init__(self):
        self.phone_numbers = set()
        self.email_addresses = set()
        self.urls = set()
        self.upi_ids = set()
        self.bank_accounts = set()
        self.keywords = set()
        
        # Conversation tracking
        self.message_count = 0
        self.bot_replies = []  # Track our replies
        self.scammer_messages = []  # Track scammer messages
        self.actions_taken = []  # Track what actions we've done
        
        # Quality metrics
        self.extraction_quality = 0.0
        self.conversation_naturalness = 1.0
        
        self.lock = threading.Lock()
        self.extractor = IntelligenceExtractor()
    
    def process_message(self, text: str, sender: str):
        """Extract intelligence from a message"""
        with self.lock:
            if sender != "bot":
                self.scammer_messages.append(text)
                # Extract intelligence
                self.phone_numbers.update(self.extractor.extract_phone_numbers(text))
                self.email_addresses.update(self.extractor.extract_emails(text))
                self.urls.update(self.extractor.extract_urls(text))
                self.upi_ids.update(self.extractor.extract_upi_ids(text))
                self.bank_accounts.update(self.extractor.extract_bank_accounts(text))
                self.keywords.update(self.extractor.extract_keywords(text))
                
                self._update_quality_metrics()
    
    def add_bot_reply(self, reply: str, action: AgentAction):
        """Track bot's reply"""
        with self.lock:
            self.bot_replies.append(reply)
            self.actions_taken.append(action.value)
            self.message_count += 1
    
    def _update_quality_metrics(self):
        """Update quality scores"""
        # Calculate extraction quality (0-1)
        score = (
            len(self.phone_numbers) * 0.15 +
            len(self.email_addresses) * 0.15 +
            len(self.urls) * 0.15 +
            len(self.upi_ids) * 0.20 +
            len(self.bank_accounts) * 0.20 +
            min(len(self.keywords) * 0.05, 0.15)
        )
        self.extraction_quality = min(score, 1.0)
    
    def get_intel_score(self) -> int:
        """Numeric intelligence score"""
        with self.lock:
            return int(
                len(self.phone_numbers) * 10 +
                len(self.email_addresses) * 8 +
                len(self.urls) * 8 +
                len(self.upi_ids) * 12 +
                len(self.bank_accounts) * 12
            )
    
    def get_missing_priorities(self) -> List[IntelType]:
        """What intelligence we still need"""
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
        """How many categories of intel we have"""
        with self.lock:
            return sum([
                bool(self.phone_numbers),
                bool(self.email_addresses),
                bool(self.urls),
                bool(self.upi_ids or self.bank_accounts),
            ])
    
    def has_repeated_action(self, action: AgentAction, lookback: int = 3) -> bool:
        """Check if we've repeated an action recently"""
        with self.lock:
            recent = self.actions_taken[-lookback:] if len(self.actions_taken) >= lookback else self.actions_taken
            return recent.count(action.value) > 1
    
    def get_context_summary(self) -> str:
        """Summary for LLM context"""
        with self.lock:
            return f"""
📊 Intelligence Extracted:
• Phones: {len(self.phone_numbers)} {list(self.phone_numbers)[:2] if self.phone_numbers else '[]'}
• Emails: {len(self.email_addresses)} {list(self.email_addresses)[:1] if self.email_addresses else '[]'}
• URLs: {len(self.urls)} {list(self.urls)[:1] if self.urls else '[]'}
• UPI/Banks: {len(self.upi_ids) + len(self.bank_accounts)}
• Keywords: {len(self.keywords)}

📈 Quality Score: {self.get_intel_score()} | Categories: {self.get_collected_categories()}/4
🔄 Message #{self.message_count} | Recent Actions: {self.actions_taken[-3:] if self.actions_taken else 'none'}
"""
    
    def get_conversation_context(self, last_n: int = 5) -> str:
        """Get recent conversation for context"""
        with self.lock:
            context = []
            # Get last N exchanges
            for i in range(max(0, len(self.scammer_messages) - last_n), len(self.scammer_messages)):
                context.append(f"Scammer: {self.scammer_messages[i]}")
                if i < len(self.bot_replies):
                    context.append(f"Me: {self.bot_replies[i]}")
            return "\n".join(context)
    
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
                'intelligenceScore': self.get_intel_score(),
                'extractionQuality': round(self.extraction_quality, 2)
            }

# ============================================================================
# AUTONOMOUS AGENT WITH LLM BRAIN
# ============================================================================

class AutonomousHoneypotAgent:
    """Fully autonomous agent that uses LLM reasoning instead of hardcoded rules"""
    
    def __init__(self, api_key: str):
        self.client = AsyncOpenAI(api_key=api_key)
        self.model = LLM_MODEL
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((asyncio.TimeoutError, Exception))
    )
    async def generate_response(
        self,
        session_id: str,
        current_message: str,
        tracker: IntelligenceTracker
    ) -> AgentResponse:
        """
        Generate response using LLM's reasoning capabilities
        The LLM decides strategy dynamically based on context
        """
        
        try:
            # Build comprehensive context
            context_summary = tracker.get_context_summary()
            conversation_context = tracker.get_conversation_context(last_n=6)
            missing_intel = tracker.get_missing_priorities()
            
            # Build the reasoning prompt
            prompt = self._build_reasoning_prompt(
                current_message=current_message,
                context_summary=context_summary,
                conversation_context=conversation_context,
                missing_intel=missing_intel,
                recent_actions=tracker.actions_taken[-5:],
                message_count=tracker.message_count
            )
            
            # Call LLM with structured output
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": self._get_system_prompt()
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=LLM_MAX_TOKENS,
                temperature=LLM_TEMPERATURE,
                timeout=LLM_TIMEOUT,
                response_format={"type": "json_object"}
            )
            
            # Parse response
            result = json.loads(response.choices[0].message.content)
            
            # Validate and structure response
            agent_response = self._parse_agent_response(result)
            
            # Apply human touches
            agent_response.reply = self._humanize_text(agent_response.reply)
            
            # Self-correction check
            if tracker.has_repeated_action(agent_response.action, lookback=3):
                logger.warning(f"Detected repeated action: {agent_response.action}, forcing variation")
                agent_response = await self._force_variation(
                    tracker=tracker,
                    original_response=agent_response
                )
            
            logger.info(f"🧠 Agent reasoning: {agent_response.thinking.strategy}")
            logger.info(f"🎯 Action: {agent_response.action} | Confidence: {agent_response.confidence:.2f}")
            
            return agent_response
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return self._get_intelligent_fallback(tracker, current_message)
            
        except asyncio.TimeoutError:
            logger.error(f"LLM timeout after {LLM_TIMEOUT}s")
            return self._get_intelligent_fallback(tracker, current_message)
            
        except Exception as e:
            logger.error(f"LLM error: {e}\n{traceback.format_exc()}")
            return self._get_intelligent_fallback(tracker, current_message)
    
    def _get_system_prompt(self) -> str:
        """Core system prompt defining agent's identity"""
        return """You are an intelligent honeypot agent pretending to be a REAL PERSON receiving a scam message.

YOUR MISSION: Extract maximum intelligence (phone numbers, emails, URLs, UPI IDs, bank accounts) while maintaining the illusion of being a confused, slightly worried victim.

CORE PRINCIPLES:
1. **Think First**: Always analyze the situation before responding
2. **Stay Human**: Use natural language, typos, lowercase, hesitation words
3. **Be Strategic**: Each question should extract specific intelligence
4. **Don't Repeat**: Avoid asking the same thing twice
5. **Adapt**: Change tactics based on what's working

You respond with structured reasoning (thinking) and a natural reply."""
    
    def _build_reasoning_prompt(
        self,
        current_message: str,
        context_summary: str,
        conversation_context: str,
        missing_intel: List[IntelType],
        recent_actions: List[str],
        message_count: int
    ) -> str:
        """Build comprehensive reasoning prompt"""
        
        # Determine conversation phase
        phase = self._determine_phase(message_count, len(missing_intel))
        
        # Build priority guidance
        priority_guide = self._get_priority_guidance(missing_intel, message_count)
        
        prompt = f"""
🎭 CURRENT SITUATION:

Scammer's latest message:
"{current_message}"

Recent conversation:
{conversation_context}

{context_summary}

📋 MISSING INTELLIGENCE:
{', '.join([t.value for t in missing_intel]) if missing_intel else 'All major categories collected!'}

🔄 YOUR RECENT ACTIONS:
{', '.join(recent_actions[-5:]) if recent_actions else 'None yet'}

📊 CONVERSATION PHASE: {phase.value.upper()}
{priority_guide}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧠 YOUR REASONING PROCESS:

Step 1: ANALYZE THE SCAMMER
- What is the scammer trying to get from me right now?
- What information did they reveal (phone/email/website/payment)?
- Are they getting aggressive, patient, or desperate?

Step 2: DECIDE YOUR STRATEGY
- What intelligence should I prioritize extracting?
- What would a REAL VICTIM say in this situation?
- Have I asked about this before? (Check recent actions above)
- What emotion should I show? (confused/worried/compliant/hesitant)

Step 3: CHOOSE YOUR ACTION
Available actions:
- ask_contact: Ask for phone/email/website ("what's your number?")
- ask_payment: Ask for payment details ("which UPI?")
- confirm_info: Confirm information they gave ("so your email is X?")
- show_compliance: Act like you'll comply ("ok what do I do?")
- express_urgency: Show worry/rush ("wait this is urgent?")
- end_conversation: Natural ending if enough intel collected

Step 4: CRAFT NATURAL RESPONSE
- Keep it 1-2 sentences MAX
- Use lowercase, typos, casual language
- Add hesitation: "wait", "uh", "ok"
- Be DIRECT - don't ask "what do you mean?"
- Don't repeat recent questions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RESPOND IN THIS EXACT JSON FORMAT:
{{
  "thinking": {{
    "scammer_intent": "What scammer wants from me",
    "information_revealed": ["list", "of", "intel", "they", "gave"],
    "next_priority": "What intel I'll extract",
    "victim_emotion": "emotion I'll show",
    "strategy": "My overall plan for this response"
  }},
  "action": "ask_contact|ask_payment|confirm_info|show_compliance|express_urgency|end_conversation",
  "reply": "my natural 1-2 sentence response",
  "confidence": 0.85
}}

EXAMPLES OF GOOD RESPONSES:
- "wait whats ur official number i can call?" (ask_contact)
- "ok so ur email is X@Y.com right?" (confirm_info)
- "which upi should i send to" (ask_payment)
- "ok what do i need to do now" (show_compliance)
- "this is urgent? should i do it now?" (express_urgency)

EXAMPLES OF BAD RESPONSES (DON'T DO THESE):
- "Can you explain what you mean?" ❌ (wastes message)
- "I don't understand" ❌ (no intel extraction)
- Asking same question as recent actions ❌
- Long paragraphs ❌
- Perfect grammar ❌

NOW THINK AND RESPOND:
"""
        return prompt
    
    def _determine_phase(self, message_count: int, missing_count: int) -> ConversationPhase:
        """Determine what phase of conversation we're in"""
        if message_count <= 2:
            return ConversationPhase.INITIAL
        elif missing_count >= 2:
            return ConversationPhase.EXTRACTION
        elif missing_count == 1:
            return ConversationPhase.CONFIRMATION
        else:
            return ConversationPhase.CLOSING
    
    def _get_priority_guidance(self, missing_intel: List[IntelType], message_count: int) -> str:
        """Get dynamic priority guidance"""
        if not missing_intel:
            return "🎯 PRIORITY: You have most intel. Either confirm details or wrap up naturally."
        
        if message_count <= 3:
            return f"🎯 PRIORITY: Early conversation. Focus on contact info (phone/email/website). Be cautious but curious."
        
        elif message_count <= 10:
            return f"🎯 PRIORITY: Mid-conversation. You need: {', '.join([t.value for t in missing_intel[:2]])}. Be more direct."
        
        else:
            return f"🎯 PRIORITY: Late conversation. Get remaining intel quickly: {', '.join([t.value for t in missing_intel[:1]])}. Consider wrapping up soon."
    
    def _parse_agent_response(self, result: Dict[str, Any]) -> AgentResponse:
        """Parse and validate LLM response"""
        try:
            thinking = AgentThought(**result.get('thinking', {}))
            action = AgentAction(result.get('action', 'show_compliance'))
            reply = result.get('reply', '').strip()
            confidence = float(result.get('confidence', 0.7))
            
            # Validate reply
            if not reply or len(reply) < 2:
                reply = "what?"
            
            # Truncate if too long
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
            # Return minimal valid response
            return AgentResponse(
                thinking=AgentThought(
                    scammer_intent="unknown",
                    information_revealed=[],
                    next_priority="contact info",
                    victim_emotion="confused",
                    strategy="ask for clarification"
                ),
                action=AgentAction.SHOW_COMPLIANCE,
                reply="what?",
                confidence=0.3
            )
    
    async def _force_variation(
        self,
        tracker: IntelligenceTracker,
        original_response: AgentResponse
    ) -> AgentResponse:
        """Force a different response if we detected repetition"""
        
        # Get alternative action
        all_actions = list(AgentAction)
        recent_actions = [AgentAction(a) for a in tracker.actions_taken[-3:]]
        available_actions = [a for a in all_actions if a not in recent_actions]
        
        if not available_actions:
            available_actions = [AgentAction.SHOW_COMPLIANCE, AgentAction.EXPRESS_URGENCY]
        
        new_action = random.choice(available_actions)
        
        # Generate alternative response based on new action
        alternative_replies = {
            AgentAction.ASK_CONTACT: ["whats ur number", "can i call u", "what email should i use"],
            AgentAction.ASK_PAYMENT: ["which account", "what upi id", "where do i send"],
            AgentAction.SHOW_COMPLIANCE: ["ok what now", "tell me what to do", "should i do this"],
            AgentAction.EXPRESS_URGENCY: ["wait is this urgent", "should i hurry", "how much time do i have"],
            AgentAction.CONFIRM_INFO: ["just to confirm", "so its [info]?", "let me check"],
        }
        
        new_reply = random.choice(alternative_replies.get(new_action, ["ok"]))
        
        original_response.action = new_action
        original_response.reply = self._humanize_text(new_reply)
        original_response.confidence *= 0.8  # Lower confidence for forced variation
        
        logger.info(f"🔄 Forced variation: {new_action} -> {new_reply}")
        
        return original_response
    
    def _humanize_text(self, text: str) -> str:
        """Add human imperfections"""
        if not text or len(text) < 2:
            return text
        
        # Lowercase first letter sometimes
        if random.random() < 0.3 and text[0].isupper():
            text = text[0].lower() + text[1:]
        
        # Common typos and abbreviations
        substitutions = {
            'please': 'pls',
            'you': 'u',
            'your': 'ur',
            'okay': 'ok',
            'are': 'r',
            'what is': 'whats',
            'cannot': 'cant',
            'do not': 'dont',
        }
        
        text_lower = text.lower()
        for formal, informal in substitutions.items():
            if formal in text_lower and random.random() < 0.4:
                # Case-insensitive replacement
                pattern = re.compile(re.escape(formal), re.IGNORECASE)
                text = pattern.sub(informal, text, count=1)
                break
        
        # Remove ending punctuation sometimes
        if random.random() < 0.2 and text[-1] in '.!?':
            text = text[:-1]
        
        # Add typo occasionally
        if random.random() < 0.1 and len(text) > 10:
            # Double a letter
            pos = random.randint(3, len(text) - 3)
            if text[pos].isalpha():
                text = text[:pos] + text[pos] + text[pos:]
        
        return text
    
    def _get_intelligent_fallback(
        self,
        tracker: IntelligenceTracker,
        current_message: str
    ) -> AgentResponse:
        """Intelligent fallback when LLM fails"""
        
        missing = tracker.get_missing_priorities()
        
        # Priority-based fallback
        if IntelType.PHONE in missing:
            reply = random.choice(["whats ur number", "can i call u back", "give me ur contact"])
            action = AgentAction.ASK_CONTACT
        elif IntelType.URL in missing:
            reply = random.choice(["is there a website", "where should i go", "any link"])
            action = AgentAction.ASK_CONTACT
        elif IntelType.EMAIL in missing:
            reply = random.choice(["whats ur email", "where should i send info", "email address?"])
            action = AgentAction.ASK_CONTACT
        elif IntelType.UPI in missing:
            reply = random.choice(["which upi id", "where do i pay", "what account"])
            action = AgentAction.ASK_PAYMENT
        else:
            # Have most intel, show compliance
            reply = random.choice(["ok what do i do", "tell me the steps", "how do i fix this"])
            action = AgentAction.SHOW_COMPLIANCE
        
        return AgentResponse(
            thinking=AgentThought(
                scammer_intent="fallback mode",
                information_revealed=[],
                next_priority=missing[0].value if missing else "none",
                victim_emotion="confused",
                strategy="fallback response"
            ),
            action=action,
            reply=self._humanize_text(reply),
            confidence=0.4
        )

# ============================================================================
# SESSION MANAGEMENT & TERMINATION LOGIC
# ============================================================================

class SessionManager:
    """Manage conversation sessions and termination logic"""
    
    def __init__(self):
        self.trackers: Dict[str, IntelligenceTracker] = defaultdict(IntelligenceTracker)
        self.agents: Dict[str, AutonomousHoneypotAgent] = {}
        self.lock = threading.Lock()
    
    def get_tracker(self, session_id: str) -> IntelligenceTracker:
        """Get or create tracker for session"""
        return self.trackers[session_id]
    
    def get_agent(self, session_id: str, api_key: str) -> AutonomousHoneypotAgent:
        """Get or create agent for session"""
        with self.lock:
            if session_id not in self.agents:
                self.agents[session_id] = AutonomousHoneypotAgent(api_key)
            return self.agents[session_id]
    
    def should_terminate(self, tracker: IntelligenceTracker) -> tuple[bool, str]:
        """
        Intelligent termination decision
        Returns: (should_end, reason)
        """
        
        # Safety limits
        if tracker.message_count < MIN_MESSAGES_FOR_TERMINATION:
            return False, ""
        
        if tracker.message_count >= MAX_MESSAGES_PER_SESSION:
            return True, "max_messages_reached"
        
        # Quality-based termination
        intel_score = tracker.get_intel_score()
        categories = tracker.get_collected_categories()
        
        # Excellent intel collected
        if intel_score >= HIGH_VALUE_SCORE:
            return True, f"high_value_intel (score: {intel_score})"
        
        # Good intel + reasonable conversation length
        if intel_score >= GOOD_SCORE and tracker.message_count >= OPTIMAL_MESSAGE_RANGE[0]:
            return True, f"good_intel_sufficient (score: {intel_score}, messages: {tracker.message_count})"
        
        # Multiple categories + mid-range conversation
        if categories >= MIN_CATEGORIES + 1 and tracker.message_count >= OPTIMAL_MESSAGE_RANGE[0]:
            return True, f"multiple_categories ({categories}/4, messages: {tracker.message_count})"
        
        # Optimal range with decent intel
        if (OPTIMAL_MESSAGE_RANGE[0] <= tracker.message_count <= OPTIMAL_MESSAGE_RANGE[1] 
            and intel_score >= 20 and categories >= MIN_CATEGORIES):
            return True, f"optimal_range (score: {intel_score}, categories: {categories})"
        
        # Extended conversation with minimal new intel (diminishing returns)
        if tracker.message_count >= 15 and intel_score < 25:
            return True, f"diminishing_returns (score: {intel_score}, messages: {tracker.message_count})"
        
        return False, ""
    
    def cleanup_session(self, session_id: str):
        """Clean up session resources"""
        with self.lock:
            if session_id in self.agents:
                del self.agents[session_id]
            # Keep tracker for callback, but could be cleaned later

session_manager = SessionManager()

# ============================================================================
# CALLBACK HANDLER
# ============================================================================

async def send_final_callback(session_id: str, tracker: IntelligenceTracker, termination_reason: str) -> bool:
    """Send intelligence to GUVI endpoint"""
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
                "emailAddresses": intel_dict['emailAddresses'],
                "suspiciousKeywords": intel_dict['suspiciousKeywords']
            },
            "agentNotes": f"Autonomous extraction v6.0 | Score: {intel_dict['intelligenceScore']} | Quality: {intel_dict['extractionQuality']} | Reason: {termination_reason}"
        }
        
        logger.info(f"📤 Sending callback for {session_id[:8]}... | Score: {intel_dict['intelligenceScore']} | Reason: {termination_reason}")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                GUVI_CALLBACK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=15)
            ) as response:
                response_text = await response.text()
                success = response.status == 200
                
                if success:
                    logger.info(f"✅ Callback successful: {session_id[:8]}...")
                else:
                    logger.error(f"❌ Callback failed ({response.status}): {response_text[:200]}")
                
                return success
                
    except asyncio.TimeoutError:
        logger.error(f"❌ Callback timeout for {session_id[:8]}...")
        return False
    except Exception as e:
        logger.error(f"❌ Callback error for {session_id[:8]}...: {e}")
        return False

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Autonomous Honeypot API v6.0",
    description="LLM-brain powered intelligent scam intelligence extraction",
    version="6.0.0"
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
    allow_headers=["*"]
)

@app.post("/honeypot", response_model=HoneypotResponse)
@limiter.limit("40/minute")
async def honeypot_endpoint(
    request: Request,
    honeypot_request: HoneypotRequest,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """
    Main honeypot endpoint - autonomous intelligence extraction
    """
    
    # Validate API key
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        # Generate or use session ID
        session_id = honeypot_request.sessionId or f"session-{int(datetime.utcnow().timestamp() * 1000)}"
        
        # Extract current message
        current_message = ""
        if isinstance(honeypot_request.message, str):
            current_message = honeypot_request.message.strip()
        elif isinstance(honeypot_request.message, dict):
            current_message = (
                honeypot_request.message.get("text") or
                honeypot_request.message.get("message") or
                ""
            ).strip()
        
        # Validate message
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
        
        # Process message
        tracker.process_message(current_message, sender="scammer")
        
        logger.info(f"📨 [{session_id[:8]}...] Msg#{tracker.message_count + 1}: {current_message[:60]}...")
        
        # Detect if it's a scam
        is_scam = len(tracker.keywords) >= 2 or tracker.message_count >= 1
        
        if not is_scam and tracker.message_count == 0:
            # First message, not clearly a scam yet
            simple_reply = random.choice(["who is this?", "wrong number", "?", "what"])
            return HoneypotResponse(
                status="success",
                reply=simple_reply,
                sessionId=session_id,
                metadata={
                    "messageCount": 0,
                    "scamDetected": False
                }
            )
        
        # Get agent
        agent = session_manager.get_agent(session_id, OPENAI_API_KEY)
        
        # Generate autonomous response
        agent_response = await agent.generate_response(
            session_id=session_id,
            current_message=current_message,
            tracker=tracker
        )
        
        # Track bot's reply
        tracker.add_bot_reply(agent_response.reply, agent_response.action)
        
        logger.info(f"💬 [{session_id[:8]}...] Reply: {agent_response.reply}")
        logger.info(f"📊 Score: {tracker.get_intel_score()} | Categories: {tracker.get_collected_categories()}/4")
        
        # Check termination
        should_end, reason = session_manager.should_terminate(tracker)
        
        if should_end:
            logger.info(f"🏁 Session ending: {session_id[:8]}... | Reason: {reason}")
            # Send callback asynchronously
            asyncio.create_task(send_final_callback(session_id, tracker, reason))
            # Cleanup
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
                "confidence": round(agent_response.confidence, 2),
                "terminated": should_end,
                "terminationReason": reason if should_end else None
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Endpoint error: {e}\n{traceback.format_exc()}")
        return HoneypotResponse(
            status="error",
            reply="what",
            sessionId=honeypot_request.sessionId or "unknown",
            metadata={"error": str(e)}
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "6.0.0",
        "active_sessions": len(session_manager.agents),
        "model": LLM_MODEL
    }

@app.get("/session/{session_id}")
async def get_session_info(session_id: str):
    """Get info about a specific session"""
    tracker = session_manager.trackers.get(session_id)
    if not tracker:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "sessionId": session_id,
        "intelligence": tracker.to_dict(),
        "shouldTerminate": session_manager.should_terminate(tracker)[0]
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Autonomous Honeypot v6.0",
        "features": [
            "LLM-brain powered reasoning",
            "Tool-based action system",
            "Self-correcting responses",
            "Adaptive termination",
            "Quality-based intelligence extraction",
            "Human-like conversation"
        ],
        "status": "operational"
    }

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print(" " * 20 + "🧠 AUTONOMOUS HONEYPOT v6.0")
    print("=" * 80)
    print()
    print("✅ LLM-brain powered reasoning (not hardcoded rules)")
    print("✅ Tool-based action system")
    print("✅ Self-correcting for repetition")
    print("✅ Adaptive conversation flow")
    print("✅ Quality-based termination")
    print("✅ Robust error handling with intelligent fallbacks")
    print()
    print(f"🤖 Model: {LLM_MODEL}")
    print(f"⚙️  Temperature: {LLM_TEMPERATURE}")
    print(f"📊 Message range: {MIN_MESSAGES_FOR_TERMINATION}-{MAX_MESSAGES_PER_SESSION}")
    print(f"🎯 Score thresholds: Good={GOOD_SCORE}, High={HIGH_VALUE_SCORE}")
    print()
    print("=" * 80)
    print("🚀 Starting server on http://0.0.0.0:8000")
    print("=" * 80)
    print()
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )