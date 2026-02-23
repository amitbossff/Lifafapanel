const TelegramBot = require('node-telegram-bot-api');

let bot = null;

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
                // Remove markdown characters and try again
                const plainText = text.replace(/[*_`[\]()]/g, '');
                await bot.sendMessage(chatId, plainText, { ...options, parse_mode: undefined });
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

// Check channel membership
async function checkChannelMembership(chatId, channel) {
    if (!bot) {
        console.log('⚠️ Bot not initialized, cannot check membership');
        return false;
    }
    
    try {
        const channelName = channel.replace('@', '');
        
        console.log(`🔍 Checking membership for user ${chatId} in channel @${channelName}`);
        
        const chatMember = await bot.getChatMember(`@${channelName}`, chatId);
        
        console.log(`📊 Member status: ${chatMember.status}`);
        
        const validStatuses = ['member', 'administrator', 'creator'];
        const isMember = validStatuses.includes(chatMember.status);
        
        console.log(`✅ Is member: ${isMember}`);
        
        return isMember;
    } catch (err) {
        console.error(`❌ Error checking channel membership for ${channel}:`, err.message);
        
        if (err.message.includes('chat not found')) {
            console.log(`⚠️ Channel @${channel} not found or bot is not admin`);
        } else if (err.message.includes('user not found')) {
            console.log(`⚠️ User ${chatId} not found in channel`);
        }
        
        return false;
    }
}

// Initialize bot
const initBot = (token) => {
    if (!token) {
        console.log('⚠️ No Telegram bot token provided');
        return null;
    }
    
    try {
        bot = new TelegramBot(token, { 
            polling: true,
            polling: {
                interval: 300,
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
            `📱 Your Telegram ID\n\n\`${chatId}\`\n\n` +
            `Use this ID for registration`
        );
    });
    
    // Handle /help command
    bot.onText(/\/help/, (msg) => {
        const chatId = msg.chat.id;
        sendHelpMessage(chatId);
    });
    
    // Handle /check command
    bot.onText(/\/check (.+)/, async (msg, match) => {
        const chatId = msg.chat.id;
        const channel = match[1];
        
        const isMember = await checkChannelMembership(chatId, channel);
        
        if (isMember) {
            sendSafeMessage(chatId, `✅ You are a member of ${channel}`);
        } else {
            sendSafeMessage(chatId, `❌ You are NOT a member of ${channel}`);
        }
    });
    
    // Handle /balance command
    bot.onText(/\/balance/, async (msg) => {
        const chatId = msg.chat.id;
        // This will be handled by the main bot instance with access to User model
        // The message will be sent from the main index.js
    });
    
    // Error handler
    bot.on('polling_error', (error) => {
        console.log('⚠️ Telegram polling error:', error.message);
    });
    
    console.log('✅ Bot handlers registered');
}

// Send welcome message
async function sendWelcomeMessage(chatId) {
    const welcomeMsg = `👋 *Welcome to MuskilxLifafa Bot!*\n\n` +
        `This bot helps you verify channel membership and receive notifications.\n\n` +
        `🔹 *Commands*\n` +
        `/id - Get your Telegram ID\n` +
        `/check <channel> - Check if you're in a channel\n` +
        `/balance - Check your balance\n` +
        `/help - Show help\n\n` +
        `🔹 *How it Works*\n` +
        `1. Register on the website with your Telegram ID\n` +
        `2. When claiming a lifafa with channels, you'll see join buttons\n` +
        `3. Join the required channels\n` +
        `4. Click Verify - we'll automatically check if you've joined\n\n` +
        `✅ *That's it!*`;
    
    await sendSafeMessage(chatId, welcomeMsg);
}

// Send help message
async function sendHelpMessage(chatId) {
    const helpMsg = `📖 *Bot Commands Help*\n\n` +
        `/start - Start the bot\n` +
        `/id - Get your Telegram ID\n` +
        `/check <channel> - Check channel membership\n` +
        `/balance - Check your balance\n` +
        `/help - Show this help\n\n` +
        `🔹 *Need Support?*\n` +
        `Contact @LifafaSupport for any issues.`;
    
    await sendSafeMessage(chatId, helpMsg);
}

// Send OTP
const sendOTP = async (chatId, otp) => {
    if (!bot) return false;
    try {
        await sendSafeMessage(chatId, 
            `🔐 *Lifafa OTP*\n\nYour OTP: \`${otp}\`\n\nValid for 5 minutes`
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
            `🔐 *Login Alert*\n\n` +
            `👤 Username: ${user.username}\n` +
            `📱 Number: ${user.number}\n` +
            `⏰ Time: ${new Date().toLocaleString()}\n` +
            `🌐 IP: ${ip || 'Unknown'}`
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
            `${emoji} *Transaction*\n\n` +
            `Type: ${type.toUpperCase()}\n` +
            `Amount: ${sign}₹${amount}\n` +
            `Balance: ₹${balance}\n` +
            `Description: ${description}`
        );
    } catch(err) {}
};

// Send withdrawal alert
const sendWithdrawalAlert = async (chatId, amount, status) => {
    if (!bot) return;
    try {
        const emoji = { 
            'pending': '⏳', 
            'approved': '✅', 
            'rejected': '❌', 
            'refunded': '↩️' 
        };
        await sendSafeMessage(chatId,
            `💸 *Withdrawal ${status.toUpperCase()}*\n\n` +
            `Status: ${emoji[status]} ${status}\n` +
            `Amount: ₹${amount}`
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
            `🎁 *New Lifafa Created!*\n\n` +
            `📌 Title: ${lifafa.title}\n` +
            `💰 Amount: ₹${lifafa.amount}\n` +
            `🔗 Link: ${claimLink}`
        );
    } catch(err) {}
};

// Send lifafa claim alert
const sendLifafaClaimAlert = async (chatId, lifafa, balance) => {
    if (!bot) return;
    try {
        await sendSafeMessage(chatId,
            `🧧 *Lifafa Claimed!*\n\n` +
            `📌 Title: ${lifafa.title}\n` +
            `💰 Amount: +₹${lifafa.amount}\n` +
            `💳 Balance: ₹${balance}`
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
