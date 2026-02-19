const TelegramBot = require('node-telegram-bot-api');

let bot = null;
const API_URL = process.env.BACKEND_URL || 'https://lifafa-backend.onrender.com';

// Helper function to escape Markdown special characters
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
        // Always use Markdown
        const sendOptions = { parse_mode: 'Markdown', ...options };
        await bot.sendMessage(chatId, text, sendOptions);
        return true;
    } catch (err) {
        // If Markdown fails, try without parse_mode
        if (err.message.includes('parse') || err.message.includes('markdown')) {
            try {
                await bot.sendMessage(chatId, text, { ...options, parse_mode: undefined });
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

const initBot = (token) => {
    if (!token) return null;
    
    try {
        bot = new TelegramBot(token, { polling: true });
        console.log('🤖 Telegram Bot Connected');
        
        // Handle /start command
        bot.onText(/\/start/, (msg) => {
            const chatId = msg.chat.id;
            const text = msg.text || '';
            
            // Check if token is provided in start command
            const tokenMatch = text.match(/\/start\s+verify_([A-Za-z0-9_]+)/);
            
            if (tokenMatch) {
                const verificationToken = tokenMatch[1];
                handleVerificationStart(chatId, verificationToken);
            } else {
                sendWelcomeMessage(chatId);
            }
        });
        
        // Handle /verify command
        bot.onText(/\/verify(?:\s+)?([A-Za-z0-9_]+)?/, async (msg, match) => {
            const chatId = msg.chat.id;
            const token = match[1];
            
            if (!token) {
                return sendSafeMessage(chatId, 
                    '❌ Please provide verification token\n\n' +
                    'Usage: /verify YOUR_TOKEN\n\n' +
                    'Example: /verify VERIFY_abc123'
                );
            }
            
            await handleVerificationStart(chatId, token);
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
        
        // Handle callback queries
        bot.on('callback_query', async (callbackQuery) => {
            const msg = callbackQuery.message;
            const chatId = msg.chat.id;
            const data = callbackQuery.data;
            
            if (data.startsWith('verify_channel_')) {
                const parts = data.split('_');
                const channel = parts.slice(2, -1).join('_'); // Handle channels with underscores
                const token = parts[parts.length - 1];
                await handleChannelVerification(callbackQuery, chatId, msg, channel, token);
            }
            else if (data === 'refresh_verification') {
                const token = msg.text.match(/Token: `([^`]+)`/)?.[1];
                if (token) {
                    await refreshVerificationStatus(callbackQuery, chatId, msg, token);
                }
            }
            else if (data === 'open_app') {
                await bot.answerCallbackQuery(callbackQuery.id, {
                    text: 'Opening app...',
                    url: process.env.FRONTEND_URL || 'https://muskilxlifafa.vercel.app'
                });
            }
            else if (data.startsWith('open_channel_')) {
                const channel = data.replace('open_channel_', '');
                await bot.answerCallbackQuery(callbackQuery.id, {
                    text: `Opening ${channel}...`,
                    url: `https://t.me/${channel.replace('@', '')}`
                });
            }
        });
        
        return bot;
    } catch(err) {
        console.log('❌ Telegram Bot Error:', err.message);
        return null;
    }
};

// Send welcome message
async function sendWelcomeMessage(chatId) {
    let replyMsg = `👋 Welcome to Lifafa Bot!\n\n`;
    replyMsg += `This bot helps you verify channels for Lifafa claims.\n\n`;
    replyMsg += `🔹 Commands\n`;
    replyMsg += `/id - Get your Telegram ID\n`;
    replyMsg += `/verify <token> - Start verification\n`;
    replyMsg += `/help - Show help\n\n`;
    replyMsg += `🔹 How to Verify\n`;
    replyMsg += `1. Get verification link from app\n`;
    replyMsg += `2. Click the link or use /verify command\n`;
    replyMsg += `3. Join required channels\n`;
    replyMsg += `4. Click verify buttons\n\n`;
    replyMsg += `✅ Once verified, valid for 48 hours!`;
    
    await sendSafeMessage(chatId, replyMsg);
}

// Send help message
async function sendHelpMessage(chatId) {
    const helpMsg = `📖 Bot Commands Help\n\n` +
        `/start - Start the bot\n` +
        `/id - Get your Telegram ID\n` +
        `/verify <token> - Verify channels using token\n` +
        `/status - Check your verification status\n` +
        `/help - Show this help\n\n` +
        `🔹 Verification Process\n` +
        `1. Get verification token from app\n` +
        `2. Send /verify YOUR_TOKEN\n` +
        `3. Join all channels listed\n` +
        `4. Click ✅ Verify buttons\n` +
        `5. All green = Verified! 🎉\n\n` +
        `🔹 Important\n` +
        `• Verification lasts 48 hours\n` +
        `• Bot must be admin in channels\n` +
        `• After verification, claim in app`;
    
    await sendSafeMessage(chatId, helpMsg);
}

// Handle verification start
async function handleVerificationStart(chatId, token) {
    try {
        // First, store user's chatId with this token
        await fetch(`${API_URL}/api/verification/save-chatid`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, chatId })
        });
        
        // Get verification status
        const response = await fetch(`${API_URL}/api/verification/status/${token}`);
        const data = await response.json();
        
        if (!data.success) {
            return sendSafeMessage(chatId, 
                '❌ Invalid or expired verification token\n\n' +
                'Please get a new verification link from the app.'
            );
        }
        
        const channels = data.channels;
        const allVerified = data.allVerified;
        
        // Create verification message
        let message = `🔐 Channel Verification\n\n`;
        message += `Token: ${token}\n`;
        message += `Status: ${allVerified ? '✅ VERIFIED' : '⏳ PENDING'}\n\n`;
        
        if (allVerified) {
            message += `✅ All channels verified!\n\n`;
            message += `You can now claim lifafas in the app.\n`;
            message += `This verification is valid for 48 hours.\n\n`;
            
            const keyboard = {
                inline_keyboard: [
                    [{ text: '🚀 Open App', callback_data: 'open_app' }]
                ]
            };
            
            return bot.sendMessage(chatId, message, {
                reply_markup: keyboard
            });
        }
        
        message += `📢 Required Channels\n\n`;
        
        // Build inline keyboard for channels
        const keyboard = {
            inline_keyboard: []
        };
        
        channels.forEach((ch) => {
            const status = ch.verified ? '✅' : '❌';
            message += `${status} ${ch.name}\n`;
            
            if (!ch.verified) {
                keyboard.inline_keyboard.push([
                    { text: `📢 Join ${ch.name}`, callback_data: `open_channel_${ch.name}` }
                ]);
                keyboard.inline_keyboard.push([
                    { text: `✅ Verify ${ch.name}`, callback_data: `verify_channel_${ch.name}_${token}` }
                ]);
            }
        });
        
        message += `\n📌 Instructions:\n`;
        message += `1. Click Join button for each channel\n`;
        message += `2. Join the channel in Telegram\n`;
        message += `3. Come back and click Verify\n`;
        message += `4. Wait for green checkmark ✅\n\n`;
        message += `⏱️ Verification valid for 48 hours`;
        
        // Add refresh button
        keyboard.inline_keyboard.push([
            { text: '🔄 Refresh Status', callback_data: 'refresh_verification' }
        ]);
        
        await bot.sendMessage(chatId, message, {
            reply_markup: keyboard
        });
        
    } catch(err) {
        console.error('Verification error:', err);
        sendSafeMessage(chatId, 
            '❌ Verification failed\n\nPlease try again later.'
        );
    }
}

// Handle channel verification
async function handleChannelVerification(callbackQuery, chatId, msg, channel, token) {
    try {
        await bot.answerCallbackQuery(callbackQuery.id, {
            text: `Verifying ${channel}...`,
            show_alert: false
        });
        
        // Call backend to verify
        const response = await fetch(`${API_URL}/api/verification/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                token, 
                channel,
                chatId 
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Get updated status
            const statusRes = await fetch(`${API_URL}/api/verification/status/${token}`);
            const statusData = await statusRes.json();
            
            // Update message
            let newMessage = `🔐 Channel Verification\n\n`;
            newMessage += `Token: ${token}\n`;
            newMessage += `Status: ${statusData.allVerified ? '✅ VERIFIED' : '⏳ PENDING'}\n\n`;
            
            if (statusData.allVerified) {
                newMessage += `✅ All channels verified!\n\n`;
                newMessage += `You can now claim lifafas in the app.\n`;
                newMessage += `This verification is valid for 48 hours.\n\n`;
                
                const keyboard = {
                    inline_keyboard: [
                        [{ text: '🚀 Open App', callback_data: 'open_app' }]
                    ]
                };
                
                await bot.editMessageText(newMessage, {
                    chat_id: chatId,
                    message_id: msg.message_id,
                    reply_markup: keyboard
                });
                
                // Send success notification
                await sendSafeMessage(chatId, 
                    `🎉 Verification Complete!\n\n` +
                    `✅ All channels verified!\n` +
                    `You can now claim lifafas in the app.`
                );
                
            } else {
                newMessage += `📢 Required Channels\n\n`;
                
                const keyboard = { inline_keyboard: [] };
                
                statusData.channels.forEach((ch) => {
                    const status = ch.verified ? '✅' : '❌';
                    newMessage += `${status} ${ch.name}\n`;
                    
                    if (!ch.verified) {
                        keyboard.inline_keyboard.push([
                            { text: `📢 Join ${ch.name}`, callback_data: `open_channel_${ch.name}` }
                        ]);
                        keyboard.inline_keyboard.push([
                            { text: `✅ Verify ${ch.name}`, callback_data: `verify_channel_${ch.name}_${token}` }
                        ]);
                    }
                });
                
                newMessage += `\n📌 Instructions:\n`;
                newMessage += `1. Click Join button for each channel\n`;
                newMessage += `2. Join the channel in Telegram\n`;
                newMessage += `3. Come back and click Verify\n`;
                newMessage += `4. Wait for green checkmark ✅`;
                
                keyboard.inline_keyboard.push([
                    { text: '🔄 Refresh Status', callback_data: 'refresh_verification' }
                ]);
                
                await bot.editMessageText(newMessage, {
                    chat_id: chatId,
                    message_id: msg.message_id,
                    reply_markup: keyboard
                });
            }
            
            // Send verification success notification
            await sendSafeMessage(chatId, 
                `✅ ${channel} verified!\n\n` +
                `${statusData.allVerified ? '🎉 All channels verified!' : 'Keep verifying remaining channels.'}`
            );
            
        } else {
            await bot.answerCallbackQuery(callbackQuery.id, {
                text: result.msg || '❌ Not a member yet. Join first!',
                show_alert: true
            });
        }
    } catch(err) {
        console.error('Channel verification error:', err);
        await bot.answerCallbackQuery(callbackQuery.id, {
            text: '❌ Verification failed',
            show_alert: true
        });
    }
}

// Refresh verification status
async function refreshVerificationStatus(callbackQuery, chatId, msg, token) {
    try {
        await bot.answerCallbackQuery(callbackQuery.id, {
            text: 'Refreshing status...',
            show_alert: false
        });
        
        const statusRes = await fetch(`${API_URL}/api/verification/status/${token}`);
        const statusData = await statusRes.json();
        
        if (!statusData.success) {
            return sendSafeMessage(chatId, '❌ Token expired');
        }
        
        let newMessage = `🔐 Channel Verification\n\n`;
        newMessage += `Token: ${token}\n`;
        newMessage += `Status: ${statusData.allVerified ? '✅ VERIFIED' : '⏳ PENDING'}\n\n`;
        
        if (statusData.allVerified) {
            newMessage += `✅ All channels verified!\n\n`;
            newMessage += `You can now claim lifafas in the app.\n`;
            newMessage += `This verification is valid for 48 hours.\n\n`;
            
            const keyboard = {
                inline_keyboard: [
                    [{ text: '🚀 Open App', callback_data: 'open_app' }]
                ]
            };
            
            await bot.editMessageText(newMessage, {
                chat_id: chatId,
                message_id: msg.message_id,
                reply_markup: keyboard
            });
        } else {
            newMessage += `📢 Required Channels\n\n`;
            
            const keyboard = { inline_keyboard: [] };
            
            statusData.channels.forEach((ch) => {
                const status = ch.verified ? '✅' : '❌';
                newMessage += `${status} ${ch.name}\n`;
                
                if (!ch.verified) {
                    keyboard.inline_keyboard.push([
                        { text: `📢 Join ${ch.name}`, callback_data: `open_channel_${ch.name}` }
                    ]);
                    keyboard.inline_keyboard.push([
                        { text: `✅ Verify ${ch.name}`, callback_data: `verify_channel_${ch.name}_${token}` }
                    ]);
                }
            });
            
            keyboard.inline_keyboard.push([
                { text: '🔄 Refresh Status', callback_data: 'refresh_verification' }
            ]);
            
            await bot.editMessageText(newMessage, {
                chat_id: chatId,
                message_id: msg.message_id,
                reply_markup: keyboard
            });
        }
        
    } catch(err) {
        console.error('Refresh error:', err);
    }
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
    sendOTP,
    sendLoginAlert,
    sendTransactionAlert,
    sendWithdrawalAlert,
    sendLifafaAlert,
    sendLifafaClaimAlert,
    sendMessage
};
