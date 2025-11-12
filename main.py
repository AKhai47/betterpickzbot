"""
Secured Combined Telegram Bot + Webhook Server
Enhanced with security, validation, idempotency, and optimization
Runs on Render.com
VERSION 2.1 - Added strict payment amount verification
"""

import os
import hmac
import hashlib
import logging
import threading
import signal
import sys
from datetime import datetime, timedelta
from typing import Optional, Dict
from functools import wraps

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests

# Import secured bot functions
from bot import (
    get_or_create_user,
    get_active_subscription,
    create_or_extend_subscription,
    save_payment,
    log_activity,
    sanitize_string,
    validate_telegram_id,
    validate_amount,
    verify_btcpay_webhook,
    invalidate_subscription_cache,
    SUPABASE_URL,
    SUPABASE_KEY,
    TELEGRAM_BOT_TOKEN,
    BTCPAY_URL,
    BTCPAY_API_KEY,
    BTCPAY_STORE_ID,
    BTCPAY_WEBHOOK_SECRET,
    SUBSCRIPTION_PRICE,
    SUBSCRIPTION_DAYS,
    TOTAL_SUBSCRIPTION_PRICE,
    supabase,
    cache
)

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('webhook_secure.log')
    ]
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)

# CORS with security
CORS(app, resources={
    r"/health": {"origins": "*"},
    r"/webhook/*": {"origins": ["*"]}  # Webhooks need to accept from BTCPay
})

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri=os.getenv('REDIS_URL', 'memory://')
)

# Idempotency tracking (prevent duplicate webhook processing)
processed_webhooks = set()  # In production, use Redis
WEBHOOK_CACHE_SIZE = 1000

def is_webhook_processed(invoice_id: str) -> bool:
    """Check if webhook was already processed"""
    if cache:
        try:
            key = f"webhook_processed:{invoice_id}"
            return cache.exists(key) > 0
        except Exception as e:
            logger.error(f"Cache check error: {e}")
    return invoice_id in processed_webhooks

def mark_webhook_processed(invoice_id: str):
    """Mark webhook as processed (with expiry)"""
    if cache:
        try:
            key = f"webhook_processed:{invoice_id}"
            cache.setex(key, 86400, "1")  # 24 hour expiry
            return
        except Exception as e:
            logger.error(f"Cache write error: {e}")
    
    # Fallback to in-memory set
    processed_webhooks.add(invoice_id)
    if len(processed_webhooks) > WEBHOOK_CACHE_SIZE:
        processed_webhooks.pop()

# Allowed table names for security (whitelist)
ALLOWED_TABLES = {'users', 'subscriptions', 'payments', 'activity_logs'}

# Supabase helper with proper error handling
def supabase_query(table: str, method: str = 'GET', filters: Dict = None, data: Dict = None) -> Optional[list]:
    """Execute Supabase query with error handling"""
    # Security: Whitelist table names to prevent unauthorized access
    if table not in ALLOWED_TABLES:
        logger.error(f"Attempted access to unauthorized table: {table}")
        return None
    
    try:
        query = supabase.table(table)
        
        if method == 'GET':
            if filters:
                for key, value in filters.items():
                    if key.startswith('eq_'):
                        query = query.eq(key[3:], value)
                    elif key.startswith('gte_'):
                        query = query.gte(key[4:], value)
            result = query.execute()
            return result.data
        
        elif method == 'POST':
            result = query.insert(data).execute()
            return result.data
        
        elif method == 'PATCH':
            if filters:
                for key, value in filters.items():
                    if key.startswith('eq_'):
                        query = query.eq(key[3:], value)
            result = query.update(data).execute()
            return result.data
        
        return None
    except Exception as e:
        logger.error(f"Supabase query error: {e}", exc_info=True)
        return None

def send_telegram_message(telegram_id: int, message: str, parse_mode: str = 'HTML'):
    """Send message via Telegram with retry"""
    if not validate_telegram_id(telegram_id):
        return False
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            response = requests.post(
                url,
                json={
                    'chat_id': telegram_id,
                    'text': message,
                    'parse_mode': parse_mode
                },
                timeout=10
            )
            
            if response.ok:
                return True
            
            logger.warning(f"Telegram API error (attempt {attempt + 1}): {response.status_code}")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Telegram request error (attempt {attempt + 1}): {e}")
        
        if attempt < max_retries - 1:
            import time
            time.sleep(2 ** attempt)  # Exponential backoff
    
    return False

# ============================================================================
# WEBHOOK ENDPOINTS
# ============================================================================

@app.route('/webhook/btcpay', methods=['POST'])
@limiter.limit("60 per minute")
def btcpay_webhook():
    """
    Handle BTCPay payment notifications
    
    Security features:
    - HMAC signature verification
    - Idempotency (prevent duplicate processing)
    - Input validation
    - STRICT AMOUNT VERIFICATION (prevents underpayments)
    - Rate limiting
    - Comprehensive error handling
    """
    try:
        # CRITICAL: Verify webhook signature (mandatory for security)
        if not BTCPAY_WEBHOOK_SECRET:
            logger.critical("BTCPAY_WEBHOOK_SECRET not configured - rejecting webhook for security")
            abort(503, "Service configuration error")
        
        signature = request.headers.get('BTCPay-Sig', '')
        if not verify_btcpay_webhook(request.data, signature):
            logger.warning(f"Invalid webhook signature from {request.remote_addr}")
            abort(401, "Invalid signature")
        
        webhook_data = request.get_json(force=True)
        
        # Validate required fields
        if not webhook_data or not isinstance(webhook_data, dict):
            logger.error("Invalid webhook payload")
            abort(400, "Invalid payload")
        
        event_type = webhook_data.get('type')
        invoice_id = webhook_data.get('invoiceId')
        
        if not event_type or not invoice_id:
            logger.error("Missing required webhook fields")
            abort(400, "Missing required fields")
        
        # Sanitize invoice_id
        invoice_id = sanitize_string(invoice_id, 100)
        
        logger.info(f"Webhook received: {event_type} for invoice {invoice_id}")
        
        # Only process relevant events
        relevant_events = ['InvoiceSettled', 'InvoiceProcessing', 'InvoiceReceivedPayment']
        if event_type not in relevant_events:
            logger.info(f"Ignoring event type: {event_type}")
            return jsonify({'status': 'ignored', 'reason': 'not_relevant'}), 200
        
        # Idempotency check
        if is_webhook_processed(invoice_id):
            logger.info(f"Webhook already processed: {invoice_id}")
            return jsonify({'status': 'already_processed'}), 200
        
        # Get payment from database
        payments = supabase_query('payments', filters={
            'eq_btcpay_invoice_id': invoice_id
        })
        
        if not payments:
            logger.error(f"Payment not found for invoice: {invoice_id[:12]}...")
            abort(404, "Payment not found")
        
        payment = payments[0]
        telegram_id = payment['user_id']
        
        # Validate telegram_id
        if not validate_telegram_id(telegram_id):
            logger.error(f"Invalid telegram_id in payment record")
            abort(400, "Invalid user ID")
        
        # Validate amount
        amount = payment.get('amount', 0)
        if not validate_amount(amount):
            logger.error(f"Invalid payment amount in payment record")
            abort(400, "Invalid amount")
        
        # ========================================================================
        # CRITICAL SECURITY CHECK: Verify amount meets subscription price
        # This prevents underpayments from activating subscriptions
        # ========================================================================
        if amount < TOTAL_SUBSCRIPTION_PRICE:
            logger.warning(
                f"🚨 INSUFFICIENT PAYMENT BLOCKED: "
                f"User paid ${amount:.2f} but needs ${TOTAL_SUBSCRIPTION_PRICE:.2f} (invoice: {invoice_id[:12]}...)"
            )
            
            # Mark as processed to prevent retry
            mark_webhook_processed(invoice_id)
            
            # Update payment status to insufficient
            supabase_query('payments', method='PATCH',
                filters={'eq_id': payment['id']},
                data={
                    'status': 'insufficient_amount',
                    'paid_at': datetime.now().isoformat(),
                    'webhook_received_at': datetime.now().isoformat()
                }
            )
            
            # Notify user about insufficient payment
            difference = TOTAL_SUBSCRIPTION_PRICE - amount
            send_telegram_message(
                telegram_id,
                f"⚠️ <b>Payment Received - Insufficient Amount</b>\n\n"
                f"💰 Amount received: <b>${amount:.2f}</b>\n"
                f"💵 Required amount: <b>${TOTAL_SUBSCRIPTION_PRICE:.2f}</b>\n"
                f"📉 Short by: <b>${difference:.2f}</b>\n\n"
                f"❌ <b>Your subscription was NOT activated.</b>\n\n"
                f"To resolve this:\n"
                f"1️⃣ Contact support for a refund\n"
                f"2️⃣ Or pay the remaining ${difference:.2f}\n\n"
                f"📧 Support: @betterpickz_support\n\n"
                f"<i>Invoice ID: {invoice_id[:12]}...</i>"
            )
            
            # Log the insufficient payment
            log_activity(telegram_id, 'payment_insufficient', {
                'invoice_id': invoice_id,
                'amount_paid': amount,
                'amount_required': TOTAL_SUBSCRIPTION_PRICE,
                'difference': difference
            })
            
            # Return error - NO SUBSCRIPTION WILL BE CREATED
            return jsonify({
                'status': 'error',
                'reason': 'insufficient_amount',
                'amount_paid': amount,
                'amount_required': TOTAL_SUBSCRIPTION_PRICE,
                'message': 'Payment amount is less than subscription price'
            }), 400
        
        # ========================================================================
        # Amount is sufficient - proceed with subscription activation
        # ========================================================================
        
        logger.info(f"✅ Payment verified: ${amount:.2f} >= ${TOTAL_SUBSCRIPTION_PRICE:.2f} (invoice: {invoice_id[:12]}...)")
        
        # Mark webhook as processed
        mark_webhook_processed(invoice_id)
        
        # Update payment status
        update_result = supabase_query('payments', method='PATCH',
            filters={'eq_id': payment['id']},
            data={
                'status': 'paid',
                'paid_at': datetime.now().isoformat(),
                'webhook_received_at': datetime.now().isoformat()
            }
        )
        
        if not update_result:
            logger.error(f"Failed to update payment status (invoice: {invoice_id[:12]}...)")
            # Don't abort - payment was processed, just log the error
        
        # Create or extend subscription
        subscription = create_or_extend_subscription(telegram_id, amount, invoice_id)
        
        if not subscription:
            logger.error(f"Failed to create/extend subscription (invoice: {invoice_id[:12]}...)")
            # Still send a notification to user
            send_telegram_message(
                telegram_id,
                "⚠️ <b>Payment Received</b>\n\n"
                "We received your payment but encountered an issue activating your subscription.\n"
                "Our support team has been notified and will resolve this shortly.\n\n"
                "Thank you for your patience!"
            )
            
            # Log critical error
            log_activity(telegram_id, 'subscription_activation_failed', {
                'invoice_id': invoice_id,
                'amount': amount
            })
            
            return jsonify({'status': 'error', 'reason': 'subscription_failed'}), 500
        
        # Link payment to subscription
        try:
            supabase_query('payments', method='PATCH',
                filters={'eq_id': payment['id']},
                data={'subscription_id': subscription['id']}
            )
            logger.info(f"Linked payment {payment['id']} to subscription {subscription['id']}")
        except Exception as e:
            logger.warning(f"Failed to link payment to subscription: {e}")
            # Non-critical error, continue
        
        # Get end date
        end_date = datetime.fromisoformat(subscription['end_date'])
        
        # Determine if this was an overpayment
        overpayment = amount - TOTAL_SUBSCRIPTION_PRICE
        overpayment_text = ""
        if overpayment > 0.01:  # More than 1 cent overpaid
            overpayment_text = f"\n\n💝 <b>Overpayment:</b> ${overpayment:.2f}\nThank you for your generosity!"
        
        # Send confirmation to user
        success = send_telegram_message(
            telegram_id,
            f"✅ <b>Payment Confirmed!</b>\n\n"
            f"🎉 Your premium subscription is now active!\n\n"
            f"📅 Valid until: {end_date.strftime('%B %d, %Y')}\n"
            f"💰 Amount paid: ${amount:.2f}{overpayment_text}\n\n"
            f"Thank you for subscribing! Enjoy your premium access! 🚀\n\n"
            f"Use /status to check your subscription anytime."
        )
        
        if not success:
            logger.error(f"Failed to send confirmation to user {telegram_id}")
        
        # Log activity
        log_activity(telegram_id, 'payment_received', {
            'invoice_id': invoice_id,
            'amount': amount,
            'end_date': end_date.isoformat(),
            'event_type': event_type,
            'overpayment': overpayment if overpayment > 0.01 else 0
        })
        
        # Send private channel invite via edge function (non-blocking)
        try:
            edge_function_url = f"{SUPABASE_URL}/functions/v1/deliver-invite"
            edge_function_key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
            
            # Security: Require service role key (don't fallback to anon key)
            if not edge_function_key:
                logger.warning("SUPABASE_SERVICE_ROLE_KEY not set - skipping invite delivery")
                # Non-critical, continue without failing webhook - invite will be skipped
            else:
                # Call edge function asynchronously (don't block webhook response)
                def send_invite_async():
                    try:
                        response = requests.post(
                            edge_function_url,
                            json={'invoiceId': invoice_id},
                            headers={
                                'Authorization': f'Bearer {edge_function_key}',
                                'Content-Type': 'application/json'
                            },
                            timeout=10
                        )
                        if response.ok:
                            logger.info(f"✅ Invite sent (invoice: {invoice_id[:12]}...)")
                        else:
                            logger.warning(f"⚠️ Invite function returned {response.status_code}")
                    except Exception as e:
                        logger.error(f"Error calling deliver-invite function: {str(e)[:100]}")
                
                # Run in background thread (non-blocking)
                invite_thread = threading.Thread(target=send_invite_async, daemon=True)
                invite_thread.start()
            
        except Exception as e:
            logger.warning(f"Failed to trigger invite delivery: {str(e)[:100]}")
            # Non-critical error, don't fail the webhook
        
        logger.info(f"✅ Webhook processed successfully (invoice: {invoice_id[:12]}...)")
        
        return jsonify({
            'status': 'success',
            'invoice_id': invoice_id,
            'user_id': telegram_id,
            'subscription_active': True
        }), 200
        
    except Exception as e:
        # Security: Log full error internally but don't expose details to client
        error_id = f"ERR_{int(datetime.now().timestamp())}"
        logger.error(f"Webhook processing error [{error_id}]: {e}", exc_info=True)
        
        # Don't expose internal errors or stack traces
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_id': error_id  # For support reference only
        }), 500


@app.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint
    Returns service status and connectivity checks
    """
    health_status = {
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'service': 'telegram-subscription-bot',
        'version': '2.1.0'
        # Security: Removed security configuration details from public endpoint
    }
    
    # Check Supabase connectivity
    try:
        result = supabase.table('users').select('id').limit(1).execute()
        health_status['database'] = 'connected'
    except Exception as e:
        # Security: Don't expose error details in health check
        logger.error(f"Health check - Supabase error: {e}")
        health_status['database'] = 'error'
        health_status['status'] = 'degraded'
    
    # Check BTCPay connectivity
    try:
        url = f"{BTCPAY_URL}/api/v1/health"
        response = requests.get(url, timeout=5)
        health_status['btcpay'] = 'connected' if response.ok else 'error'
    except Exception as e:
        # Security: Don't expose error details in health check
        logger.error(f"Health check - BTCPay error: {e}")
        health_status['btcpay'] = 'error'
        health_status['status'] = 'degraded'
    
    # Check cache
    health_status['cache'] = 'enabled' if cache else 'disabled'
    
    status_code = 200 if health_status['status'] == 'ok' else 503
    return jsonify(health_status), status_code


@app.route('/webhook/test', methods=['POST'])
@limiter.limit("10 per minute")
def webhook_test():
    """Test endpoint for webhook verification (development only)"""
    if os.getenv('FLASK_ENV') != 'development':
        abort(404)
    
    return jsonify({
        'status': 'test_ok',
        'headers': dict(request.headers),
        'body': request.get_json()
    }), 200


@app.errorhandler(400)
def bad_request(e):
    """Handle bad requests"""
    logger.warning(f"Bad request: {e}")
    return jsonify({'error': 'Bad request', 'message': str(e)}), 400


@app.errorhandler(401)
def unauthorized(e):
    """Handle unauthorized requests"""
    logger.warning(f"Unauthorized request: {e}")
    return jsonify({'error': 'Unauthorized'}), 401


@app.errorhandler(404)
def not_found(e):
    """Handle not found errors"""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return jsonify({'error': 'Rate limit exceeded', 'message': str(e)}), 429


@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    logger.error(f"Internal error: {e}", exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500


# ============================================================================
# APPLICATION LIFECYCLE
# ============================================================================

bot_thread = None
flask_running = False

def run_flask():
    """Run Flask server"""
    global flask_running
    port = int(os.getenv('PORT', 8080))
    
    logger.info(f"Starting Flask webhook server on port {port}")
    flask_running = True
    
    # In production, use a proper WSGI server
    if os.getenv('FLASK_ENV') == 'production':
        from waitress import serve
        serve(app, host='0.0.0.0', port=port, threads=4)
    else:
        app.run(host='0.0.0.0', port=port, debug=False)


def run_bot():
    """Run Telegram bot"""
    from bot import main as bot_main
    logger.info("Starting Telegram bot")
    bot_main()


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global flask_running
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    flask_running = False
    sys.exit(0)


def main():
    """Main entry point"""
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Validate environment
    required_vars = [
        'TELEGRAM_BOT_TOKEN',
        'SUPABASE_URL',
        'SUPABASE_KEY',
        'BTCPAY_URL',
        'BTCPAY_API_KEY',
        'BTCPAY_STORE_ID',
        'BTCPAY_WEBHOOK_SECRET'  # Security: Now required
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        logger.critical(f"Missing required environment variables: {', '.join(missing_vars)}")
        logger.critical("⚠️  BTCPAY_WEBHOOK_SECRET is now REQUIRED for security!")
        sys.exit(1)
    
    if not cache:
        logger.warning("⚠️  Redis not configured - rate limiting and caching will use fallbacks")
    
    logger.info("=" * 60)
    logger.info("🚀 Starting Secured Telegram Subscription Bot v2.1")
    logger.info("=" * 60)
    logger.info(f"Environment: {os.getenv('FLASK_ENV', 'production')}")
    logger.info(f"Subscription: ${SUBSCRIPTION_PRICE} + fee = ${TOTAL_SUBSCRIPTION_PRICE} for {SUBSCRIPTION_DAYS} days")
    logger.info(f"Security features:")
    logger.info(f"  - Amount verification: ✅ ENABLED (STRICT)")
    logger.info(f"  - Webhook verification: ✅ ENABLED (REQUIRED)")
    logger.info(f"  - Rate limiting: {'✅ Enabled' if cache else '⚠️  Fallback mode'}")
    logger.info(f"  - Input validation: ✅ Enabled")
    logger.info(f"  - Idempotency: ✅ Enabled")
    logger.info(f"  - CORS protection: ✅ Enabled")
    logger.info(f"  - Security headers: ✅ Enabled")
    logger.info("=" * 60)
    
    try:
        # Start Flask in a separate thread
        global bot_thread
        flask_thread = threading.Thread(target=run_flask, daemon=False, name="FlaskWebhook")
        flask_thread.start()
        
        # Give Flask time to start
        import time
        time.sleep(2)
        
        logger.info("✅ Flask webhook server started")
        logger.info("✅ Starting Telegram bot...")
        
        # Run bot in main thread
        run_bot()
        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()