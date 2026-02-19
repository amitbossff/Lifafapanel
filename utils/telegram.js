const TelegramBot = require('node-telegram-bot-api');

let bot = null;
const API_URL = process.env.BACKEND_URL || 'https://lifafa-backend.onrender.com';

// Helper function to escape Markdown
function escapeMarkdown(text) {
    if (!text) return '';
    return text
        .replace(/_/g, '\\_')
        .replace(/\*/g, '\\*')
        .replace(/\[/g, '\\[')
        .replace(/\]/g, '\\]')
        .replace(/\(/g, '\\(')
        .replace(/\)/g, '\\)')
        .replace(/~/g, '\\~')
        .replace(/`/g, '\\`')
        .replace(/>/g, '\\>')
        .replace(/#/g, '\\#')
        .replace(/\+/g, '\\+')
        .replace(/-/g, '\\-')
        .replace(/=/g, '\\=')
        .replace(/\|/g, '\\|')
        .replace(/\{/g, '\\{')
        .replace(/\}/g, '\\}')
        .replace(/\./g, '\\.')
        .replace(/!/g, '\\!');
}

// Safe send message function
async function sendSafeMessage(chatId, text, options = {}) {
    if (!bot) return false;
    try {
        const sendOptions = { parse_mode: 'Markdown', ...options };
        await bot.sendMessage(chatId, text, sendOptions);
        return true;
    } catch (err) {
        if (err.message.includes('parse') || err.message.includes('markdown')) {
            try {
                await bot.sendMessage(chatId, text.replace(/[*_`[\]()]/g, ''), { ...options, parse_mode: undefined });
                return true;
            } catch (secondErr) {
                console.error('Both send attempts failed:', secondErr.message);
                return false;
            }
        }
        console.error('Send message error:', err.message);
        return false;
    }
}

// Check if user is member of a channel
async function checkChannelMembership(chatId, channel) {
    if (!bot) return false;
    try {
        // Remove @ from channel name if present
        const channelName = channel.replace('@', '');
        
        // Get chat member information
        const chatMember = await bot.getChatMember(`@${channelName}`, chatId);
        
        // Check if user is member (status: 'member', 'administrator', or 'creator')
        const validStatuses = ['member', 'administrator', 'creator'];
        return validStatuses.includes(chatMember.status);
    } catch (err) {
        console.error(`Error checking channel membership for ${channel}:`, err.message);
        return false;
    }
}

const initBot = (token) => {
    if (!token) {
        console.log('⚠️ No Telegram bot token provided');
        return null;
    }
    
    try {
        // ✅ FIX: Always use polling mode for Render
        // Webhook mode causes issues on free hosting
        bot = new TelegramBot(token, { 
            polling: true,
            // Optional: Add polling options
            polling: {
                interval: 300, // Optional: polling interval in ms
                autoStart: true,
                params: {
                    timeout: 10
                }
            }
        });
        
        console.log('🤖 Telegram Bot Connected with polling mode');
        setupBotHandlers();
        
        return bot;
    } catch(err) {
        console.log('❌ Telegram Bot Error:', err.message);
        return null;
    }
};

// Setup bot handlers
function setupBotHandlers() {
    if (!bot) return;
    
    // Handle /start command
    bot.onText(/\/start/, (msg) => {
        const chatId = msg.chat.id;
        sendWelcomeMessage(chatId);
    });
    
    // Handle /id command
    bot.onText(/\/id/, (msg) => {
        const chatId = msg.chat.id;
        sendSafeMessage(chatId, 
            `📱 Your Telegram ID\n\n${chatId}\n\n` +
            `Use this ID for registration`
        );
    });
    
    // Handle /help command
    bot.onText(/\/help/, (msg) => {
        const chatId = msg.chat.id;
        sendHelpMessage(chatId);
    });
    
    // Handle /verify command (for manual verification)
    bot.onText(/\/verify/, (msg) => {
        const chatId = msg.chat.id;
        sendSafeMessage(chatId, 
            `🔐 *Verification*\n\n` +
            `To verify channels, please use the website.\n` +
            `1. Go to the claim page\n` +
            `2. Enter your number\n` +
            `3. Follow the channel join instructions`,
            { parse_mode: 'Markdown' }
        );
    });
    
    // Error handler
    bot.on('polling_error', (error) => {
        console.log('⚠️ Telegram polling error:', error.message);
    });
    
    console.log('✅ Bot handlers registered');
}

// Send welcome message
async function sendWelcomeMessage(chatId) {
    const welcomeMsg = `👋 Welcome to Lifafa Bot!\n\n` +
        `This bot helps verify your channel membership for Lifafa claims.\n\n` +
        `🔹 Commands\n` +
        `/id - Get your Telegram ID\n` +
        `/help - Show help\n\n` +
        `🔹 How it Works\n` +
        `1. Register on the website with your Telegram ID\n` +
        `2. When claiming a lifafa with channels, you'll see join buttons\n` +
        `3. Join the required channels\n` +
        `4. Click Verify & Claim - we'll automatically check if you've joined\n\n` +
        `✅ That's it! No separate verification needed.`;
    
    await sendSafeMessage(chatId, welcomeMsg);
}

// Send help message
async function sendHelpMessage(chatId) {
    const helpMsg = `📖 Bot Commands Help\n\n` +
        `/start - Start the bot\n` +
        `/id - Get your Telegram ID\n` +
        `/help - Show this help\n\n` +
        `🔹 Need Support?\n` +
        `Contact @LifafaSupport for any issues.`;
    
    await sendSafeMessage(chatId, helpMsg);
}

// Send OTP
const sendOTP = async (chatId, otp) => {
    if (!bot) return false;
    try {
        await sendSafeMessage(chatId, 
            `🔐 Lifafa OTP\n\nYour OTP: ${otp}\n\nValid for 5 minutes`
        );
        return true;
    } catch(err) {
        return false;
    }
};

// Send login alert
const sendLoginAlert = async (chatId, user, ip) => {
    if (!bot) return;
    try {
        await sendSafeMessage(chatId,
            `🔐 Login Alert\n\n👤 Username: ${user.username}\n📱 Number: ${user.number}\n⏰ Time: ${new Date().toLocaleString()}\n🌐 IP: ${ip || 'Unknown'}`
        );
    } catch(err) {}
};

// Send transaction alert
const sendTransactionAlert = async (chatId, type, amount, balance, description) => {
    if (!bot) return;
    try {
        const emoji = type === 'credit' ? '💰' : '💸';
        const sign = type === 'credit' ? '+' : '-';
        await sendSafeMessage(chatId,
            `${emoji} Transaction\n\nType: ${type.toUpperCase()}\nAmount: ${sign}₹${amount}\nBalance: ₹${balance}\nDescription: ${description}`
        );
    } catch(err) {}
};

// Send withdrawal alert
const sendWithdrawalAlert = async (chatId, amount, status) => {
    if (!bot) return;
    try {
        const emoji = { 'pending': '⏳', 'approved': '✅', 'rejected': '❌', 'refunded': '↩️' };
        await sendSafeMessage(chatId,
            `💸 Withdrawal ${status.toUpperCase()}\n\nStatus: ${emoji[status]} ${status}\nAmount: ₹${amount}`
        );
    } catch(err) {}
};

// Send lifafa alert
const sendLifafaAlert = async (chatId, lifafa) => {
    if (!bot) return;
    try {
        const baseUrl = process.env.FRONTEND_URL || 'https://muskilxlifafa.vercel.app';
        const claimLink = `${baseUrl}/claimlifafa.html?code=${lifafa.code}`;
        await sendSafeMessage(chatId,
            `🎁 New Lifafa Created!\n\n📌 Title: ${lifafa.title}\n💰 Amount: ₹${lifafa.amount}\n🔗 Link: ${claimLink}`
        );
    } catch(err) {}
};

// Send lifafa claim alert
const sendLifafaClaimAlert = async (chatId, lifafa, balance) => {
    if (!bot) return;
    try {
        await sendSafeMessage(chatId,
            `🧧 Lifafa Claimed!\n\n📌 Title: ${lifafa.title}\n💰 Amount: +₹${lifafa.amount}\n💳 Balance: ₹${balance}`
        );
    } catch(err) {}
};

// Send custom message
const sendMessage = async (chatId, text, options = {}) => {
    if (!bot) return false;
    try {
        await bot.sendMessage(chatId, text, options);
        return true;
    } catch(err) {
        return false;
    }
};

module.exports = {
    initBot,
    checkChannelMembership,
    sendOTP,
    sendLoginAlert,
    sendTransactionAlert,
    sendWithdrawalAlert,
    sendLifafaAlert,
    sendLifafaClaimAlert,
    sendMessage
};
