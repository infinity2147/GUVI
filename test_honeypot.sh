#!/bin/bash

# Simple Honeypot Termination Checker
# Tests different termination conditions

API_KEY="Xk7pQm9RvT2nL5wY8hJcA1bN4fG6dS3e"
BASE_URL="https://honeypot-f1pp.onrender.com"

echo "======================================================================"
echo "    HONEYPOT TERMINATION CONDITION TESTS"
echo "======================================================================"
echo ""
echo "Choose a test:"
echo ""
echo "1. Test 20-message limit (sends 22 messages rapidly)"
echo "2. Test critical intel extraction (send bank account)"
echo "3. Test high scam score termination (obvious scam messages)"
echo "4. Continue your existing conversation (adds 10 more messages)"
echo ""
read -p "Enter choice (1-4): " CHOICE
echo ""

SESSION_ID="term-test-$(date +%s)"

case $CHOICE in
    1)
        echo "Testing 20-message limit..."
        echo "Session ID: $SESSION_ID"
        echo ""
        
        for i in {1..22}; do
            echo -n "Message $i/22... "
            REPLY=$(curl -s -X POST "$BASE_URL/honeypot" \
                -H "Content-Type: application/json" \
                -H "x-api-key: $API_KEY" \
                -d "{
                    \"sessionId\": \"$SESSION_ID\",
                    \"message\": \"Your SBI account will be blocked. Share OTP now! Message $i\"
                }" | jq -r '.reply')
            
            echo "Reply: $REPLY"
            
            if [ $i -eq 20 ]; then
                echo ""
                echo "🔴 TERMINATION POINT REACHED (20 messages)"
                echo "Callback should be sent now. Check logs!"
                echo ""
            fi
            
            sleep 0.5
        done
        ;;
        
    2)
        echo "Testing critical intel extraction..."
        echo "Session ID: $SESSION_ID"
        echo ""
        
        # Send a few warm-up messages
        for i in {1..3}; do
            echo "Message $i/3..."
            curl -s -X POST "$BASE_URL/honeypot" \
                -H "Content-Type: application/json" \
                -H "x-api-key: $API_KEY" \
                -d "{
                    \"sessionId\": \"$SESSION_ID\",
                    \"message\": \"Your account needs verification $i\"
                }" > /dev/null
            sleep 0.5
        done
        
        echo ""
        echo "🎯 Sending message with bank account and UPI..."
        REPLY=$(curl -s -X POST "$BASE_URL/honeypot" \
            -H "Content-Type: application/json" \
            -H "x-api-key: $API_KEY" \
            -d "{
                \"sessionId\": \"$SESSION_ID\",
                \"message\": \"Sir please transfer to account 1234567890123456 or UPI test@paytm immediately\"
            }" | jq -r '.reply')
        
        echo "Reply: $REPLY"
        echo ""
        echo "🔴 CRITICAL INTEL DETECTED"
        echo "Session should terminate immediately!"
        echo "Check logs for callback with extracted:"
        echo "  - Bank Account: 1234567890123456"
        echo "  - UPI ID: test@paytm"
        ;;
        
    3)
        echo "Testing high scam score termination..."
        echo "Session ID: $SESSION_ID"
        echo ""
        
        # Send 6 obviously scammy messages
        SCAM_MSGS=(
            "URGENT URGENT URGENT! Your account blocked! Share OTP password PIN CVV now!"
            "IMMEDIATE ACTION REQUIRED! Bank account suspended! Click link and verify!"
            "WARNING: Legal action! Court case! Police! Share account details immediately!"
            "CONGRATULATIONS! You won lottery prize! Share bank details to claim reward!"
            "This is Income Tax Department! Pay penalty! Share account and OTP now!"
            "Your account hacked! Unauthorized transaction! Share OTP PIN PASSWORD now!"
        )
        
        for i in {0..5}; do
            echo "Message $((i+1))/6..."
            curl -s -X POST "$BASE_URL/honeypot" \
                -H "Content-Type: application/json" \
                -H "x-api-key: $API_KEY" \
                -d "{
                    \"sessionId\": \"$SESSION_ID\",
                    \"message\": \"${SCAM_MSGS[$i]}\"
                }" > /dev/null
            sleep 0.5
        done
        
        echo ""
        echo "🔴 HIGH SCAM SCORE REACHED (80%+)"
        echo "Session should terminate after message 5+"
        echo "Check logs for termination!"
        ;;
        
    4)
        echo "Continuing existing conversation..."
        echo ""
        read -p "Enter your existing session ID: " EXISTING_ID
        
        if [ -z "$EXISTING_ID" ]; then
            echo "No session ID provided. Exiting."
            exit 1
        fi
        
        echo ""
        echo "Sending 10 additional messages to session: $EXISTING_ID"
        echo ""
        
        for i in {1..10}; do
            echo "Additional message $i/10..."
            REPLY=$(curl -s -X POST "$BASE_URL/honeypot" \
                -H "Content-Type: application/json" \
                -H "x-api-key: $API_KEY" \
                -d "{
                    \"sessionId\": \"$EXISTING_ID\",
                    \"message\": \"Sir please share account number and OTP urgently. Message $i\"
                }" | jq -r '.reply')
            echo "Reply: $REPLY"
            echo ""
            sleep 1
        done
        ;;
        
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "======================================================================"
echo "    TEST COMPLETE"
echo "======================================================================"
echo ""
echo "Session ID: $SESSION_ID"
echo ""
echo "CHECK RENDER LOGS NOW:"
echo "1. Go to: https://dashboard.render.com"
echo "2. Select: honeypot-f1pp service"
echo "3. Click: Logs tab"
echo ""
echo "LOOK FOR:"
echo "  ✓ Callback sent for session $SESSION_ID: 200"
echo "  Session terminated after XX messages"
echo ""
echo "CALLBACK PAYLOAD SHOULD INCLUDE:"
echo "  - sessionId: $SESSION_ID"
echo "  - scamDetected: true"
echo "  - totalMessagesExchanged: XX"
echo "  - extractedIntelligence: {bankAccounts, upiIds, phoneNumbers, etc}"
echo "  - agentNotes: Scam type and tactics"
echo ""
echo "VERIFY ON GUVI:"
echo "Check your GUVI hackathon dashboard for the final result submission"
echo ""
echo "======================================================================"