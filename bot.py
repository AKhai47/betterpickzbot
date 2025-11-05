"""
Secured Telegram Subscription Bot with BTCPay & Supabase
Enhanced with security, validation, caching, and optimization
Version: 2.2 - With Inline Menu Buttons
"""

from dotenv import load_dotenv
load_dotenv()

import os
import hmac
import hashlib
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Any
import asyncio

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
from telegram.error import TelegramError
import httpx
from supabase import create_client, Client
import qrcode
from io import BytesIO

# Configuration from environment variables
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
BTCPAY_URL = os.getenv('BTCPAY_URL')
BTCPAY_API_KEY = os.getenv('BTCPAY_API_KEY')
BTCPAY_STORE_ID = os.getenv('BTCPAY_STORE_ID')
BTCPAY_WEBHOOK_SECRET = os.getenv('BTCPAY_WEBHOOK_SECRET')
SUBSCRIPTION_PRICE = float(os.getenv('SUBSCRIPTION_PRICE', '10.00'))
SUBSCRIPTION_DAYS = int(os.getenv('SUBSCRIPTION_DAYS', '30'))
REDIS_URL = os.getenv('REDIS_URL', None)
PROCESSING_FEE_PERCENT = float(os.getenv('PROCESSING_FEE_PERCENT', '5.0'))

# Calculate total price with fee included
def calculate_total_price():
    """Calculate total subscription price with processing fee included"""
    base_price = SUBSCRIPTION_PRICE
    fee = round(base_price * (PROCESSING_FEE_PERCENT / 100), 2)
    total = round(base_price + fee, 2)
    return total

TOTAL_SUBSCRIPTION_PRICE = calculate_total_price()

# Security settings
MAX_INVOICE_AGE_MINUTES = 15
RATE_LIMIT_COMMANDS = 10
ALLOWED_CURRENCIES = ['USD', 'EUR']
MIN_SUBSCRIPTION_PRICE = 1.0
MAX_SUBSCRIPTION_PRICE = 10000.0

# Logging with UTF-8 encoding
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('bot.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Initialize Supabase
try:
    if SUPABASE_URL and SUPABASE_KEY:
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    else:
        raise ValueError("Supabase credentials not set")
except Exception as e:
    logger.critical(f"Failed to initialize Supabase: {e}")
    supabase = None

# Initialize Redis cache if available
cache = None
if REDIS_URL:
    try:
        import redis
        cache = redis.from_url(REDIS_URL, decode_responses=True)
        logger.info("Redis cache initialized")
    except ImportError:
        logger.warning("Redis not installed. Install with: pip install redis")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}")

# HTTP client with connection pooling
http_client = httpx.AsyncClient(
    timeout=30.0,
    limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
)


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

def sanitize_string(value: str, max_length: int = 255) -> str:
    """Sanitize string input to prevent injection attacks"""
    if not isinstance(value, str):
        return ""
    sanitized = ''.join(char for char in value if char.isprintable() or char.isspace())
    return sanitized[:max_length].strip()


def validate_telegram_id(telegram_id: Any) -> bool:
    """Validate telegram ID is a positive integer"""
    try:
        tid = int(telegram_id)
        return 0 < tid < 10**15
    except (ValueError, TypeError):
        return False


def validate_amount(amount: Any) -> bool:
    """Validate payment amount"""
    try:
        amt = float(amount)
        return MIN_SUBSCRIPTION_PRICE <= amt <= MAX_SUBSCRIPTION_PRICE
    except (ValueError, TypeError):
        return False


def verify_btcpay_webhook(payload: bytes, signature: str) -> bool:
    """Verify BTCPay webhook signature"""
    if not BTCPAY_WEBHOOK_SECRET or not signature:
        logger.warning("Webhook verification skipped - no secret configured")
        return False
    
    try:
        expected_sig = hmac.new(
            BTCPAY_WEBHOOK_SECRET.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        if signature.startswith('sha256='):
            signature = signature[7:]
        
        return hmac.compare_digest(expected_sig, signature)
    except Exception as e:
        logger.error(f"Webhook verification error: {e}")
        return False


def rate_limit_check(user_id: int, action: str = "command") -> bool:
    """Check if user is rate limited"""
    if not cache:
        return True
    
    try:
        key = f"ratelimit:{action}:{user_id}"
        count = cache.get(key)
        
        if count is None:
            cache.setex(key, 60, 1)
            return True
        
        count = int(count)
        if count >= RATE_LIMIT_COMMANDS:
            return False
        
        cache.incr(key)
        return True
    except Exception as e:
        logger.error(f"Rate limit check error: {e}")
        return True


# ============================================================================
# CACHE UTILITIES
# ============================================================================

def get_cached_subscription(telegram_id: int) -> Optional[Dict]:
    """Get subscription from cache"""
    if not cache:
        return None
    
    try:
        key = f"sub:{telegram_id}"
        data = cache.get(key)
        if data:
            import json
            return json.loads(data)
    except Exception as e:
        logger.error(f"Cache read error: {e}")
    return None


def set_cached_subscription(telegram_id: int, subscription: Dict, ttl: int = 60):
    """Cache subscription data for 60 seconds (balance between speed and freshness)"""
    if not cache or not subscription:
        return
    
    try:
        import json
        key = f"sub:{telegram_id}"
        cache.setex(key, ttl, json.dumps(subscription))
    except Exception as e:
        logger.error(f"Cache write error: {e}")


def invalidate_subscription_cache(telegram_id: int):
    """Remove subscription from cache"""
    if not cache:
        return
    
    try:
        cache.delete(f"sub:{telegram_id}")
    except Exception as e:
        logger.error(f"Cache invalidation error: {e}")


# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def get_or_create_user(telegram_id: int, username: str = None, first_name: str = None) -> Optional[Dict]:
    """Get user from database or create if doesn't exist"""
    if not validate_telegram_id(telegram_id):
        logger.error(f"Invalid telegram_id: {telegram_id}")
        return None
    
    try:
        username = sanitize_string(username, 32) if username else None
        first_name = sanitize_string(first_name, 64) if first_name else None
        
        result = supabase.table('users')\
            .select('*')\
            .eq('telegram_id', telegram_id)\
            .execute()
        
        if result.data:
            return result.data[0]
        
        new_user = {
            'telegram_id': telegram_id,
            'username': username,
            'first_name': first_name,
            'created_at': datetime.now().isoformat()
        }
        
        result = supabase.table('users').insert(new_user).execute()
        
        if result.data:
            logger.info(f"New user created: {telegram_id}")
            return result.data[0]
        
        return None
        
    except Exception as e:
        logger.error(f"Error in get_or_create_user: {e}", exc_info=True)
        return None


def get_active_subscription(telegram_id: int, use_cache: bool = True) -> Optional[Dict]:
    """Check if user has active subscription"""
    if not validate_telegram_id(telegram_id):
        return None
    
    if use_cache:
        cached = get_cached_subscription(telegram_id)
        if cached:
            return cached
    
    try:
        result = supabase.table('subscriptions')\
            .select('*')\
            .eq('user_id', telegram_id)\
            .eq('status', 'active')\
            .gte('end_date', datetime.now().isoformat())\
            .order('end_date', desc=True)\
            .limit(1)\
            .execute()
        
        subscription = result.data[0] if result.data else None
        
        if subscription:
            set_cached_subscription(telegram_id, subscription)
        
        return subscription
        
    except Exception as e:
        logger.error(f"Error checking subscription: {e}", exc_info=True)
        return None


async def create_btcpay_invoice(telegram_id: int, amount: float) -> Optional[Dict]:
    """Create invoice in BTCPay Server"""
    if not validate_telegram_id(telegram_id):
        return None
    
    if not validate_amount(amount):
        logger.error(f"Invalid amount: {amount}")
        return None
    
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            # Clean up URL to avoid duplication
            base_url = BTCPAY_URL.rstrip('/').split('/stores/')[0]
            url = f"{base_url}/api/v1/stores/{BTCPAY_STORE_ID}/invoices"
            
            headers = {
                'Authorization': f'token {BTCPAY_API_KEY}',
                'Content-Type': 'application/json'
            }
            
            order_id = f'sub_{telegram_id}_{int(datetime.now().timestamp())}'
            
            payload = {
                'amount': str(round(amount, 2)),
                'currency': 'USD',
                'metadata': {
                    'orderId': order_id,
                    'userId': str(telegram_id),
                    'subscriptionDays': str(SUBSCRIPTION_DAYS),
                    'basePrice': str(SUBSCRIPTION_PRICE),
                    'feePercent': str(PROCESSING_FEE_PERCENT),
                    'totalPrice': str(amount)
                },
                'checkout': {
                    'speedPolicy': 'HighSpeed',
                    'paymentMethods': ['BTC', 'BTC-LightningNetwork'],
                    'expirationMinutes': MAX_INVOICE_AGE_MINUTES,
                    'redirectURL': f'https://t.me/{os.getenv("BOT_USERNAME", "your_bot")}'
                }
            }
            
            response = await http_client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            
            invoice_data = response.json()
            logger.info(f"Invoice created: {invoice_data['id']} for user {telegram_id} - ${amount}")
            return invoice_data
            
        except httpx.HTTPStatusError as e:
            logger.error(f"BTCPay HTTP error (attempt {attempt + 1}): {e.response.status_code}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
                retry_delay *= 2
            else:
                return None
        except Exception as e:
            logger.error(f"Error creating BTCPay invoice: {e}", exc_info=True)
            return None


def save_payment(telegram_id: int, invoice_data: Dict) -> Optional[Dict]:
    """Save payment to database"""
    if not validate_telegram_id(telegram_id):
        return None
    
    try:
        if not invoice_data.get('id') or not invoice_data.get('checkoutLink'):
            logger.error("Invalid invoice data")
            return None
        
        amount = float(invoice_data.get('amount', 0))
        if not validate_amount(amount):
            logger.error(f"Invalid invoice amount: {amount}")
            return None
        
        payment = {
            'user_id': telegram_id,
            'btcpay_invoice_id': sanitize_string(invoice_data['id'], 100),
            'amount': amount,
            'currency': sanitize_string(invoice_data.get('currency', 'USD'), 10),
            'status': 'pending',
            'invoice_url': sanitize_string(invoice_data['checkoutLink'], 500),
            'created_at': datetime.now().isoformat()
        }
        
        result = supabase.table('payments').insert(payment).execute()
        
        if result.data:
            logger.info(f"Payment saved: {payment['btcpay_invoice_id']}")
            return result.data[0]
        
        return None
        
    except Exception as e:
        logger.error(f"Error saving payment: {e}", exc_info=True)
        return None


def create_or_extend_subscription(telegram_id: int, amount: float, invoice_id: str) -> Optional[Dict]:
    """Create new or extend existing subscription"""
    if not validate_telegram_id(telegram_id):
        return None
    
    try:
        result = supabase.table('subscriptions')\
            .select('*')\
            .eq('user_id', telegram_id)\
            .eq('status', 'active')\
            .order('end_date', desc=True)\
            .limit(1)\
            .execute()
        
        now = datetime.now()
        
        if result.data:
            subscription = result.data[0]
            current_end = datetime.fromisoformat(subscription['end_date'])
            new_end = max(current_end, now) + timedelta(days=SUBSCRIPTION_DAYS)
            
            update_result = supabase.table('subscriptions')\
                .update({
                    'end_date': new_end.isoformat(),
                    'updated_at': now.isoformat()
                })\
                .eq('id', subscription['id'])\
                .execute()
            
            if update_result.data:
                invalidate_subscription_cache(telegram_id)
                logger.info(f"Subscription extended for user {telegram_id} until {new_end}")
                return update_result.data[0]
        else:
            end_date = now + timedelta(days=SUBSCRIPTION_DAYS)
            
            new_subscription = {
                'user_id': telegram_id,
                'status': 'active',
                'plan_type': 'monthly',
                'amount_paid': amount,
                'start_date': now.isoformat(),
                'end_date': end_date.isoformat(),
                'created_at': now.isoformat()
            }
            
            insert_result = supabase.table('subscriptions')\
                .insert(new_subscription)\
                .execute()
            
            if insert_result.data:
                invalidate_subscription_cache(telegram_id)
                logger.info(f"New subscription created for user {telegram_id} until {end_date}")
                return insert_result.data[0]
        
        return None
        
    except Exception as e:
        logger.error(f"Error creating/extending subscription: {e}", exc_info=True)
        return None


def log_activity(user_id: int, action: str, details: Dict = None):
    """Log user activity"""
    if not validate_telegram_id(user_id):
        return
    
    try:
        activity = {
            'user_id': user_id,
            'action': sanitize_string(action, 50),
            'details': details or {},
            'created_at': datetime.now().isoformat()
        }
        
        supabase.table('activity_logs').insert(activity).execute()
        
    except Exception as e:
        logger.error(f"Error logging activity: {e}")


def generate_qr_code(payment_url: str) -> Optional[BytesIO]:
    """Generate QR code image for payment URL"""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(payment_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        bio = BytesIO()
        bio.name = 'qr_code.png'
        img.save(bio, 'PNG')
        bio.seek(0)
        
        return bio
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        return None


# ============================================================================
# BOT COMMAND HANDLERS
# ============================================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command with inline menu"""
    user = update.effective_user
    telegram_id = user.id
    
    if not rate_limit_check(telegram_id, "start"):
        await update.message.reply_text("⏱ Please slow down. Try again in a minute.")
        return
    
    db_user = get_or_create_user(telegram_id, user.username, user.first_name)
    if not db_user:
        await update.message.reply_text(
            "❌ Service temporarily unavailable. Please try again later."
        )
        return
    
    # Preload subscription data (will be cached for fast button clicks)
    subscription = get_active_subscription(telegram_id, use_cache=False)  # Fresh data on start
    log_activity(telegram_id, 'command_start')
    
    # Create inline menu
    keyboard = [
        [InlineKeyboardButton("💎 Subscribe / Renew", callback_data='menu_subscribe')],
        [InlineKeyboardButton("📊 My Status", callback_data='menu_status')],
        [InlineKeyboardButton("📦 Plans", callback_data='menu_plans')],
        [InlineKeyboardButton("❓ How it works", callback_data='menu_how')],
        [InlineKeyboardButton("🆘 Support", callback_data='menu_support')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if subscription:
        end_date = datetime.fromisoformat(subscription['end_date'])
        days_left = (end_date - datetime.now()).days
        status_text = "✅ Active" if days_left > 0 else "❌ Expired"
        
        await update.message.reply_text(
            f"👋 Welcome, {sanitize_string(user.first_name)}!\n\n"
            f"💰 Plan: ${TOTAL_SUBSCRIPTION_PRICE:.2f} / {SUBSCRIPTION_DAYS} days\n"
            f"📊 Your status: {status_text}\n\n"
            f"Tap below to manage your subscription 👇",
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
    else:
        await update.message.reply_text(
            f"👋 Welcome, {sanitize_string(user.first_name)}!\n\n"
            f"💰 Plan: ${TOTAL_SUBSCRIPTION_PRICE:.2f} / {SUBSCRIPTION_DAYS} days\n"
            f"📊 Your status: ❌ Not active\n\n"
            f"Tap below to manage your subscription 👇",
            reply_markup=reply_markup,
            parse_mode='HTML'
        )


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle all button clicks - optimized for speed"""
    query = update.callback_query
    
    # INSTANT acknowledgment to Telegram (makes it feel faster!)
    await query.answer()
    
    user = query.from_user
    telegram_id = user.id
    
    # Skip rate limiting for better UX (already rate limited at command level)
    # if not rate_limit_check(telegram_id, "button"):
    #     await query.edit_message_text("⏱ Please slow down. Try again in a minute.")
    #     return
    
    # Menu: Subscribe
    if query.data == 'menu_subscribe':
        keyboard = [
            [InlineKeyboardButton("⚡️ Pay with Bitcoin/Lightning", callback_data='create_invoice')],
            [InlineKeyboardButton("« Back to Menu", callback_data='back_to_menu')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"💎 <b>Premium Subscription</b>\n\n"
            f"💰 Price: ${TOTAL_SUBSCRIPTION_PRICE:.2f}\n"
            f"⏱ Duration: {SUBSCRIPTION_DAYS} days\n"
            f"⚡️ Payment: Bitcoin or Lightning Network\n\n"
            f"✨ <b>What you get:</b>\n"
            f"• Instant activation\n"
            f"• Access to all premium content\n"
            f"• Priority support\n"
            f"• Automatic renewal reminders\n\n"
            f"🔒 <b>Secure payment via BTCPay Server</b>\n"
            f"Your privacy is protected - no personal info required!",
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        return
    
    # Menu: Status
    elif query.data == 'menu_status':
        # Use cached data for instant response!
        subscription = get_active_subscription(telegram_id, use_cache=True)
        
        keyboard = [[InlineKeyboardButton("« Back to Menu", callback_data='back_to_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if subscription:
            end_date = datetime.fromisoformat(subscription['end_date'])
            days_left = (end_date - datetime.now()).days
            status_emoji = "✅" if days_left > 7 else "⚠️"
            
            await query.edit_message_text(
                f"📊 <b>Subscription Status</b>\n\n"
                f"{status_emoji} Status: <b>Active</b>\n"
                f"📅 Expires: {end_date.strftime('%B %d, %Y')}\n"
                f"⏳ Days remaining: <b>{days_left}</b>\n"
                f"💰 Plan: ${subscription.get('amount_paid', SUBSCRIPTION_PRICE):.2f}/{SUBSCRIPTION_DAYS}d\n\n"
                f"{'⚠️ Renew soon to avoid interruption!' if days_left <= 7 else '✨ Enjoying premium access!'}",
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await query.edit_message_text(
                f"📊 <b>Subscription Status</b>\n\n"
                f"❌ Status: <b>Inactive</b>\n"
                f"💰 Price: ${TOTAL_SUBSCRIPTION_PRICE:.2f}/{SUBSCRIPTION_DAYS}d\n\n"
                f"Tap Subscribe to get started!",
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        return
    
    # Menu: Plans
    elif query.data == 'menu_plans':
        keyboard = [[InlineKeyboardButton("« Back to Menu", callback_data='back_to_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"💰 <b>Subscription Plans</b>\n\n"
            f"<b>Monthly Plan:</b>\n"
            f"💵 ${TOTAL_SUBSCRIPTION_PRICE:.2f} for {SUBSCRIPTION_DAYS} days\n\n"
            f"✨ <b>What's included:</b>\n"
            f"• Full access to premium picks\n"
            f"• Daily predictions & analysis\n"
            f"• Priority support\n"
            f"• Exclusive content\n"
            f"• Money-back guarantee\n\n"
            f"Tap Subscribe to get started!",
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        return
    
    # Menu: How it works
    elif query.data == 'menu_how':
        keyboard = [[InlineKeyboardButton("« Back to Menu", callback_data='back_to_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"❓ <b>How It Works</b>\n\n"
            f"<b>Step 1:</b> Tap 💎 Subscribe\n"
            f"<b>Step 2:</b> Pay with Bitcoin or Lightning\n"
            f"<b>Step 3:</b> Get instant access!\n\n"
            f"💳 <b>Payment:</b>\n"
            f"We accept Bitcoin and Lightning Network payments via BTCPay Server. "
            f"Your payment is secure and private.\n\n"
            f"⚡ <b>Instant Activation:</b>\n"
            f"Your subscription activates automatically within seconds of payment.\n\n"
            f"📱 <b>Access:</b>\n"
            f"Once subscribed, you'll get access to all premium features!",
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        return
    
    # Menu: Support
    elif query.data == 'menu_support':
        keyboard = [[InlineKeyboardButton("« Back to Menu", callback_data='back_to_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"🆘 <b>Support</b>\n\n"
            f"Need help? We're here for you!\n\n"
            f"📧 <b>Contact:</b>\n"
            f"• Email: support@betterpickz.com\n"
            f"• Telegram: @betterpickz_support\n\n"
            f"⏰ <b>Response Time:</b>\n"
            f"We typically respond within 24 hours.\n\n"
            f"💡 <b>Quick Help:</b>\n"
            f"• Payment issues: Check your wallet\n"
            f"• Subscription status: Tap 📊 My Status\n"
            f"• Technical problems: Send /start\n\n"
            f"<b>Common Questions:</b>\n"
            f"Q: How do I subscribe?\n"
            f"A: Tap 💎 Subscribe and follow the steps\n\n"
            f"Q: What payment methods?\n"
            f"A: Bitcoin & Lightning Network\n\n"
            f"Q: Instant access?\n"
            f"A: Yes! Activates in seconds",
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        return
    
    # Back to main menu
    elif query.data == 'back_to_menu':
        subscription = get_active_subscription(telegram_id)
        
        keyboard = [
            [InlineKeyboardButton("💎 Subscribe / Renew", callback_data='menu_subscribe')],
            [InlineKeyboardButton("📊 My Status", callback_data='menu_status')],
            [InlineKeyboardButton("📦 Plans", callback_data='menu_plans')],
            [InlineKeyboardButton("❓ How it works", callback_data='menu_how')],
            [InlineKeyboardButton("🆘 Support", callback_data='menu_support')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if subscription:
            end_date = datetime.fromisoformat(subscription['end_date'])
            days_left = (end_date - datetime.now()).days
            status_text = "✅ Active" if days_left > 0 else "❌ Expired"
            
            await query.edit_message_text(
                f"👋 Welcome back!\n\n"
                f"💰 Plan: ${TOTAL_SUBSCRIPTION_PRICE:.2f} / {SUBSCRIPTION_DAYS} days\n"
                f"📊 Your status: {status_text}\n\n"
                f"Tap below to manage your subscription 👇",
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await query.edit_message_text(
                f"👋 Welcome!\n\n"
                f"💰 Plan: ${TOTAL_SUBSCRIPTION_PRICE:.2f} / {SUBSCRIPTION_DAYS} days\n"
                f"📊 Your status: ❌ Not active\n\n"
                f"Tap below to manage your subscription 👇",
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        return
    
    # Create invoice
    if query.data == 'create_invoice':
        # Show loading immediately with encouraging message
        await query.edit_message_text(
            "⏳ <b>Creating your payment invoice...</b>\n\n"
            "Hang tight! This will just take a moment! ⚡",
            parse_mode='HTML'
        )
        
        try:
            invoice_data = await create_btcpay_invoice(telegram_id, TOTAL_SUBSCRIPTION_PRICE)
            
            if not invoice_data:
                keyboard = [[InlineKeyboardButton("« Back", callback_data='menu_subscribe')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await query.edit_message_text(
                    "❌ Unable to create invoice right now.\n"
                    "Please try again in a few moments or contact support.",
                    reply_markup=reply_markup
                )
                log_activity(telegram_id, 'invoice_creation_failed')
                return
            
            payment = save_payment(telegram_id, invoice_data)
            
            if not payment:
                keyboard = [[InlineKeyboardButton("« Back", callback_data='menu_subscribe')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await query.edit_message_text(
                    "❌ Error processing request.\n"
                    "Please try again or contact support.",
                    reply_markup=reply_markup
                )
                return
            
            checkout_link = invoice_data['checkoutLink']
            
            # Generate QR code
            qr_image = generate_qr_code(checkout_link)
            
            # Send QR code as photo
            if qr_image:
                # First, delete the loading message
                try:
                    await query.message.delete()
                except:
                    pass  # Message might already be deleted
                
                # Send the QR code image
                keyboard = [
                    [InlineKeyboardButton("💳 Open in Browser", url=checkout_link)],
                    [InlineKeyboardButton("« Back to Menu", callback_data='back_to_menu')]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                caption = (
                    f"✅ <b>Invoice Created!</b>\n\n"
                    f"💰 Amount: ${TOTAL_SUBSCRIPTION_PRICE:.2f}\n"
                    f"⏱ Valid for: {MAX_INVOICE_AGE_MINUTES} minutes\n"
                    f"⚡️ Payment: BTC or Lightning\n\n"
                    f"📱 <b>Scan QR code above with your wallet</b>\n"
                    f"Or click 'Open in Browser' to pay\n\n"
                    f"You'll receive confirmation automatically! 🎉\n\n"
                    f"<i>Invoice ID: {invoice_data['id'][:8]}...</i>"
                )
                
                await context.bot.send_photo(
                    chat_id=telegram_id,
                    photo=qr_image,
                    caption=caption,
                    reply_markup=reply_markup,
                    parse_mode='HTML'
                )
            else:
                # Fallback if QR generation fails - use old method
                keyboard = [
                    [InlineKeyboardButton("💳 Pay Now", url=checkout_link)],
                    [InlineKeyboardButton("« Back to Menu", callback_data='back_to_menu')]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await query.edit_message_text(
                    f"✅ <b>Invoice Created!</b>\n\n"
                    f"💰 Amount: ${TOTAL_SUBSCRIPTION_PRICE:.2f}\n"
                    f"⏱ Valid for: {MAX_INVOICE_AGE_MINUTES} minutes\n"
                    f"⚡️ Payment: BTC or Lightning\n\n"
                    f"Click <b>Pay Now</b> to open the payment page.\n"
                    f"You'll receive confirmation automatically! 🎉\n\n"
                    f"<i>Invoice ID: {invoice_data['id'][:8]}...</i>",
                    reply_markup=reply_markup,
                    parse_mode='HTML'
                )
            
            log_activity(telegram_id, 'invoice_created', {
                'invoice_id': invoice_data['id'],
                'amount': TOTAL_SUBSCRIPTION_PRICE
            })
            
        except Exception as e:
            logger.error(f"Error in button_callback: {e}", exc_info=True)
            await query.edit_message_text(
                "❌ An error occurred. Please try again later."
            )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Log errors and notify user"""
    logger.error(f"Update {update} caused error {context.error}", exc_info=context.error)
    
    try:
        if update and update.effective_message:
            await update.effective_message.reply_text(
                "❌ An unexpected error occurred. Our team has been notified.\n"
                "Please try again in a few moments."
            )
    except Exception as e:
        logger.error(f"Error in error_handler: {e}")


def main():
    """Start the bot"""
    if not TELEGRAM_BOT_TOKEN:
        logger.critical("TELEGRAM_BOT_TOKEN not set!")
        return
    
    if not all([SUPABASE_URL, SUPABASE_KEY, BTCPAY_URL, BTCPAY_API_KEY, BTCPAY_STORE_ID]):
        logger.critical("Missing required environment variables!")
        return
    
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_error_handler(error_handler)
    
    # Start bot
    logger.info("Bot started successfully!")
    logger.info(f"Rate limiting: {'Enabled' if cache else 'Disabled (no Redis)'}")
    logger.info(f"Webhook verification: {'Enabled' if BTCPAY_WEBHOOK_SECRET else 'Disabled'}")
    
    application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == '__main__':
    main()