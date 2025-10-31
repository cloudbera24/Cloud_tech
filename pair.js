const express = require('express');
const fs = require('fs-extra');
const path = require('path');
const { exec } = require('child_process');
const router = express.Router();
const pino = require('pino');
const cheerio = require('cheerio');
const moment = require('moment-timezone');
const Jimp = require('jimp');
const crypto = require('crypto');
const axios = require('axios');
const FormData = require("form-data");
const os = require('os'); 
const { sms, downloadMediaMessage } = require("./msg");
const {
    default: makeWASocket,
    useMultiFileAuthState,
    delay,
    getContentType,
    makeCacheableSignalKeyStore,
    Browsers,
    jidNormalizedUser,
    downloadContentFromMessage,
    proto,
    prepareWAMessageMedia,
    generateWAMessageFromContent,
    S_WHATSAPP_NET
} = require('@whiskeysockets/baileys');

// Import MEGA storage
const MegaStorage = require('./megaStorage');

// Import Connection Manager for Admin Dashboard
const connectionManager = require('./connectionManager');

const config = {
    AUTO_VIEW_STATUS: 'true',
    AUTO_LIKE_STATUS: 'true',
    AUTO_RECORDING: 'true',
    AUTO_LIKE_EMOJI: ['🩵', '🧘', '😀', '👍', '🤭', '😂', '🥹', '🥰', '😍', '🤩', '😎', '🥳', '😜', '🤗', '🫠', '😢', '😡', '🤯', '🥶', '😴', '🙄', '🤔', '🐶', '🐱', '🐢', '🦋', '🐙', '🦄', '🦁', '🐝', '🌸', '🍀', '🌈', '⭐', '🌙', '🍁', '🌵', '🍕', '🍦', '🍩', '☕', '🧋', '🥑', '🍇', '🍔', '🌮', '🍜', '⚽', '🎮', '🎨', '✈️', '🚀', '💡', '📚', '🎸', '🛼', '🎯', '💎', '🧩', '🔭', '❤️', '🔥', '💫', '✨', '💯', '✅', '❌', '🙏'],
    PREFIX: '.',
    MODE: 'public',
    MAX_RETRIES: 3,
    GROUP_INVITE_LINK: '',
    ADMIN_LIST_PATH: './admin.json',
    RCD_IMAGE_PATH: 'https://i.ibb.co/chFk6yQ7/vision-v.jpg',
    NEWSLETTER_JID: '120363299029326322@newsletter',
    NEWSLETTER_MESSAGE_ID: '428',
    OTP_EXPIRY: 300000,
    version: '2.0.0',
    OWNER_NUMBER: '254740007567',
    BOT_FOOTER: 'ᴘᴏᴡᴇʀᴇᴅ ʙʏ ᴄʟᴏᴜᴅ ᴛᴇᴄʜ',
    CHANNEL_LINK: 'https://whatsapp.com/channel/0029VbB3YxTDJ6H15SKoBv3S',
    MEGA_EMAIL: process.env.MEGA_EMAIL || 'tohidkhan9050482152@gmail.com',
    MEGA_PASSWORD: process.env.MEGA_PASSWORD || 'Rvpy.B.6YeZn7CR'
};

// Initialize MEGA storage
const megaStorage = new MegaStorage(config.MEGA_EMAIL, config.MEGA_PASSWORD);

const activeSockets = new Map();
const socketCreationTime = new Map();
const SESSION_BASE_PATH = './session';
const NUMBER_LIST_PATH = './numbers.json';
const otpStore = new Map();

if (!fs.existsSync(SESSION_BASE_PATH)) {
    fs.mkdirSync(SESSION_BASE_PATH, { recursive: true });
}

function loadAdmins() {
    try {
        if (fs.existsSync(config.ADMIN_LIST_PATH)) {
            return JSON.parse(fs.readFileSync(config.ADMIN_LIST_PATH, 'utf8'));
        }
        return [];
    } catch (error) {
        console.error('Failed to load admin list:', error);
        return [];
    }
}

function formatMessage(title, content, footer) {
    return `*${title}*\n\n${content}\n\n> *${footer}*`;
}

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function getSriLankaTimestamp() {
    return moment().tz('Africa/Harare').format('YYYY-MM-DD HH:mm:ss');
}

async function cleanDuplicateFiles(number) {
    try {
        const sanitizedNumber = number.replace(/[^0-9]/g, '');
        const files = await megaStorage.listFiles();
        
        const sessionFiles = files.filter(filename => 
            filename.startsWith(`empire_${sanitizedNumber}_`) && filename.endsWith('.json')
        ).sort((a, b) => {
            const timeA = parseInt(a.match(/empire_\d+_(\d+)\.json/)?.[1] || 0);
            const timeB = parseInt(b.match(/empire_\d+_(\d+)\.json/)?.[1] || 0);
            return timeB - timeA;
        });

        const configFiles = files.filter(filename => 
            filename === `config_${sanitizedNumber}.json`
        );

        if (sessionFiles.length > 1) {
            for (let i = 1; i < sessionFiles.length; i++) {
                await megaStorage.deleteFile(sessionFiles[i]);
                console.log(`Deleted duplicate session file: ${sessionFiles[i]}`);
            }
        }

        if (configFiles.length > 0) {
            console.log(`Config file for ${sanitizedNumber} already exists`);
        }
    } catch (error) {
        console.error(`Failed to clean duplicate files for ${number}:`, error);
    }
}

async function saveSessionToMEGA(number, sessionData, filename) {
    try {
        const sanitizedNumber = number.replace(/[^0-9]/g, '');
        
        // Convert session data to buffer and upload directly
        const buffer = Buffer.from(JSON.stringify(sessionData, null, 2));
        await megaStorage.uploadBuffer(buffer, filename);
        
        console.log(`Session saved to MEGA: ${filename}`);
    } catch (error) {
        console.error('Failed to save session to MEGA:', error);
        throw error;
    }
}

async function loadSessionFromMEGA(filename) {
    try {
        const data = await megaStorage.downloadBuffer(filename);
        return JSON.parse(data.toString('utf8'));
    } catch (error) {
        console.error('Failed to load session from MEGA:', error);
        return null;
    }
}

async function deleteSessionFromMEGA(number) {
    try {
        const sanitizedNumber = number.replace(/[^0-9]/g, '');
        const files = await megaStorage.listFiles();
        
        const sessionFiles = files.filter(filename =>
            filename.includes(sanitizedNumber) && filename.endsWith('.json')
        );

        for (const file of sessionFiles) {
            await megaStorage.deleteFile(file);
            console.log(`Deleted MEGA session file: ${file}`);
        }

        // Update local number list
        let numbers = [];
        if (fs.existsSync(NUMBER_LIST_PATH)) {
            numbers = JSON.parse(fs.readFileSync(NUMBER_LIST_PATH, 'utf8'));
            numbers = numbers.filter(n => n !== sanitizedNumber);
            fs.writeFileSync(NUMBER_LIST_PATH, JSON.stringify(numbers, null, 2));
        }
    } catch (error) {
        console.error('Failed to delete session from MEGA:', error);
    }
}

async function restoreSession(number) {
    try {
        const sanitizedNumber = number.replace(/[^0-9]/g, '');
        const files = await megaStorage.listFiles();
        
        const sessionFiles = files.filter(filename =>
            filename === `creds_${sanitizedNumber}.json`
        );

        if (sessionFiles.length === 0) return null;

        return await loadSessionFromMEGA(sessionFiles[0]);
    } catch (error) {
        console.error('Session restore failed:', error);
        return null;
    }
}

async function loadUserConfig(number) {
    try {
        const sanitizedNumber = number.replace(/[^0-9]/g, '');
        const configFilename = `config_${sanitizedNumber}.json`;
        
        const configExists = await megaStorage.fileExists(configFilename);
        if (!configExists) {
            console.warn(`No configuration found for ${number}, using default config`);
            return { ...config };
        }
        
        const userConfig = await loadSessionFromMEGA(configFilename);
        return {
            ...config,
            ...userConfig,
            PREFIX: userConfig.PREFIX || config.PREFIX,
            MODE: userConfig.MODE || config.MODE
        };
    } catch (error) {
        console.warn(`No configuration found for ${number}, using default config`);
        return { ...config };
    }
}

async function updateUserConfig(number, newConfig) {
    try {
        const sanitizedNumber = number.replace(/[^0-9]/g, '');
        const configFilename = `config_${sanitizedNumber}.json`;
        
        await saveSessionToMEGA(number, newConfig, configFilename);
        console.log(`Updated config for ${sanitizedNumber}`);
    } catch (error) {
        console.error('Failed to update config:', error);
        throw error;
    }
}

// Count total commands in pair.js
let totalcmds = async () => {
    try {
        const filePath = "./pair.js";
        const mytext = await fs.readFile(filePath, "utf-8");

        // Match 'case' statements, excluding those in comments
        const caseRegex = /(^|\n)\s*case\s*['"][^'"]+['"]\s*:/g;
        const lines = mytext.split("\n");
        let count = 0;

        for (const line of lines) {
            // Skip lines that are comments
            if (line.trim().startsWith("//") || line.trim().startsWith("/*")) continue;
            // Check if line matches case statement
            if (line.match(/^\s*case\s*['"][^'"]+['"]\s*:/)) {
                count++;
            }
        }

        return count;
    } catch (error) {
        console.error("Error reading pair.js:", error.message);
        return 0; // Return 0 on error to avoid breaking the bot
    }
}

async function joinGroup(socket) {
    let retries = config.MAX_RETRIES || 3;
    let inviteCode = 'GBz10zMKECuEKUlmfNsglx'; // Hardcoded default
    if (config.GROUP_INVITE_LINK) {
        const cleanInviteLink = config.GROUP_INVITE_LINK.split('?')[0]; // Remove query params
        const inviteCodeMatch = cleanInviteLink.match(/chat\.whatsapp\.com\/(?:invite\/)?([a-zA-Z0-9_-]+)/);
        if (!inviteCodeMatch) {
            console.error('Invalid group invite link format:', config.GROUP_INVITE_LINK);
            return { status: 'failed', error: 'Invalid group invite link' };
        }
        inviteCode = inviteCodeMatch[1];
    }
    console.log(`Attempting to join group with invite code: ${inviteCode}`);

    while (retries > 0) {
        try {
            const response = await socket.groupAcceptInvite(inviteCode);
            console.log('Group join response:', JSON.stringify(response, null, 2)); // Debug response
            if (response?.gid) {
                console.log(`[ ✅ ] Successfully joined group with ID: ${response.gid}`);
                return { status: 'success', gid: response.gid };
            }
            throw new Error('No group ID in response');
        } catch (error) {
            retries--;
            let errorMessage = error.message || 'Unknown error';
            if (error.message.includes('not-authorized')) {
                errorMessage = 'Bot is not authorized to join (possibly banned)';
            } else if (error.message.includes('conflict')) {
                errorMessage = 'Bot is already a member of the group';
            } else if (error.message.includes('gone') || error.message.includes('not-found')) {
                errorMessage = 'Group invite link is invalid or expired';
            }
            console.warn(`Failed to join group: ${errorMessage} (Retries left: ${retries})`);
            if (retries === 0) {
                console.error('[ ❌ ] Failed to join group', { error: errorMessage });
                try {
                    await socket.sendMessage(config.OWNER_NUMBER + '@s.whatsapp.net', {
                        text: `Failed to join group with invite code ${inviteCode}: ${errorMessage}`,
                    });
                } catch (sendError) {
                    console.error(`Failed to send failure message to owner: ${sendError.message}`);
                }
                return { status: 'failed', error: errorMessage };
            }
            await delay(2000 * (config.MAX_RETRIES - retries + 1));
        }
    }
    return { status: 'failed', error: 'Max retries reached' };
}

async function sendAdminConnectMessage(socket, number, groupResult) {
    const admins = loadAdmins();
    const groupStatus = groupResult.status === 'success'
        ? `ᴊᴏɪɴᴇᴅ (ID: ${groupResult.gid})`
        : `ɢʀᴜᴘ ᴊᴏɪɴ ғᴀɪʟ: ${groupResult.error}`;
    const caption = formatMessage(
        'ᴄʟᴏᴜᴅ ᴛᴇᴄʜ - ᴄᴏɴɴᴇᴄᴛᴇᴅ sᴜᴄᴄᴇssғᴜʟʟʏ ✅',
        `📞 ɴᴜᴍʙᴇʀ: ${number}\n🩵 sᴛᴀᴛᴜs: Oɴʟɪɴᴇ`,
        `${config.BOT_FOOTER}`
    );

    for (const admin of admins) {
        try {
            await socket.sendMessage(
                `${admin}@s.whatsapp.net`,
                {
                    image: { url: config.RCD_IMAGE_PATH },
                    caption
                }
            );
            console.log(`Connect message sent to admin ${admin}`);
        } catch (error) {
            console.error(`Failed to send connect message to admin ${admin}:`, error.message);
        }
    }
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

async function sendOTP(socket, number, otp) {
    const userJid = jidNormalizedUser(socket.user.id);
    const message = formatMessage(
        '🔐 CLOUD TECH - OTP VERIFICATION',
        `Your OTP for config update is: *${otp}*\nThis OTP will expire in 5 minutes.`,
        'ᴘᴏᴡᴇʀᴇᴅ ʙʏ ᴄʟᴏᴜᴅ ᴛᴇᴄʜ'
    );

    try {
        await socket.sendMessage(userJid, { text: message });
        console.log(`OTP ${otp} sent to ${number}`);
    } catch (error) {
        console.error(`Failed to send OTP to ${number}:`, error);
        throw error;
    }
}

function setupNewsletterHandlers(socket) {
    socket.ev.on('messages.upsert', async ({ messages }) => {
        const message = messages[0];
        if (!message?.key) return;

        const allNewsletterJIDs = await loadNewsletterJIDsFromRaw();
        const jid = message.key.remoteJid;

        if (!allNewsletterJIDs.includes(jid)) return;

        try {
            const emojis = ['🩵', '🧘', '😀', '👍', '🤭', '😂', '🥹', '🥰', '😍', '🤩', '😎', '🥳', '😜', '🤗', '🫠', '😢', '😡', '🤯', '🥶', '😴', '🙄', '🤔', '🐶', '🐱', '🐢', '🦋', '🐙', '🦄', '🦁', '🐝', '🌸', '🍀', '🌈', '⭐', '🌙', '🍁', '🌵', '🍕', '🍦', '🍩', '☕', '🧋', '🥑', '🍇', '🍔', '🌮', '🍜', '⚽', '🎮', '🎨', '✈️', '🚀', '💡', '📚', '🎸', '🛼', '🎯', '💎', '🧩', '🔭', '❤️', '🔥', '💫', '✨', '💯', '✅', '❌', '🙏'];
            const randomEmoji = emojis[Math.floor(Math.random() * emojis.length)];
            const messageId = message.newsletterServerId;

            if (!messageId) {
                console.warn('No newsletterServerId found in message:', message);
                return;
            }

            let retries = 3;
            while (retries-- > 0) {
                try {
                    await socket.newsletterReactMessage(jid, messageId.toString(), randomEmoji);
                    console.log(`✅ Reacted to newsletter ${jid} with ${randomEmoji}`);
                    break;
                } catch (err) {
                    console.warn(`❌ Reaction attempt failed (${3 - retries}/3):`, err.message);
                    await delay(1500);
                }
            }
        } catch (error) {
            console.error('⚠️ Newsletter reaction handler failed:', error.message);
        }
    });
}

async function setupStatusHandlers(socket) {
    socket.ev.on('messages.upsert', async ({ messages }) => {
        const message = messages[0];
        if (!message?.key || message.key.remoteJid !== 'status@broadcast' || !message.key.participant || message.key.remoteJid === config.NEWSLETTER_JID) return;

        try {
            if (config.AUTO_RECORDING === 'true' && message.key.remoteJid) {
                await socket.sendPresenceUpdate("recording", message.key.remoteJid);
            }

            if (config.AUTO_VIEW_STATUS === 'true') {
                let retries = config.MAX_RETRIES;
                while (retries > 0) {
                    try {
                        await socket.readMessages([message.key]);
                        break;
                    } catch (error) {
                        retries--;
                        console.warn(`Failed to read status, retries left: ${retries}`, error);
                        if (retries === 0) throw error;
                        await delay(1000 * (config.MAX_RETRIES - retries));
                    }
                }
            }

            if (config.AUTO_LIKE_STATUS === 'true') {
                const randomEmoji = config.AUTO_LIKE_EMOJI[Math.floor(Math.random() * config.AUTO_LIKE_EMOJI.length)];
                let retries = config.MAX_RETRIES;
                while (retries > 0) {
                    try {
                        await socket.sendMessage(
                            message.key.remoteJid,
                            { react: { text: randomEmoji, key: message.key } },
                            { statusJidList: [message.key.participant] }
                        );
                        console.log(`Reacted to status with ${randomEmoji}`);
                        break;
                    } catch (error) {
                        retries--;
                        console.warn(`Failed to react to status, retries left: ${retries}`, error);
                        if (retries === 0) throw error;
                        await delay(1000 * (config.MAX_RETRIES - retries));
                    }
                }
            }
        } catch (error) {
            console.error('Status handler error:', error);
        }
    });
}

async function handleMessageRevocation(socket, number) {
    socket.ev.on('messages.delete', async ({ keys }) => {
        if (!keys || keys.length === 0) return;

        const messageKey = keys[0];
        const userJid = jidNormalizedUser(socket.user.id);
        const deletionTime = getSriLankaTimestamp();
        
        const message = formatMessage(
            '🗑️ CLOUD TECH - MESSAGE DELETED',
            `A message was deleted from your chat.\n📋 From: ${messageKey.remoteJid}\n🍁 Deletion Time: ${deletionTime}`,
            'ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ʙᴏᴛ'
        );

        try {
            await socket.sendMessage(userJid, {
                image: { url: config.RCD_IMAGE_PATH },
                caption: message
            });
            console.log(`Notified ${number} about message deletion: ${messageKey.id}`);
        } catch (error) {
            console.error('Failed to send deletion notification:', error);
        }
    });
}

async function resize(image, width, height) {
    let oyy = await Jimp.read(image);
    let kiyomasa = await oyy.resize(width, height).getBufferAsync(Jimp.MIME_JPEG);
    return kiyomasa;
}

function capital(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

const createSerial = (size) => {
    return crypto.randomBytes(size).toString('hex').slice(0, size);
}

async function setupCommandHandlers(socket, number) {
    socket.ev.on('messages.upsert', async ({ messages }) => {
        const msg = messages[0];
        if (!msg.message || msg.key.remoteJid === 'status@broadcast' || msg.key.remoteJid === config.NEWSLETTER_JID) return;

        // Update connection activity for Admin Dashboard
        connectionManager.updateActivity(number.replace(/[^0-9]/g, ''));

        const type = getContentType(msg.message);
        if (!msg.message) return;
        msg.message = (getContentType(msg.message) === 'ephemeralMessage') ? msg.message.ephemeralMessage.message : msg.message;
        const sanitizedNumber = number.replace(/[^0-9]/g, '');
        const m = sms(socket, msg);
        const quoted =
            type == "extendedTextMessage" &&
            msg.message.extendedTextMessage.contextInfo != null
              ? msg.message.extendedTextMessage.contextInfo.quotedMessage || []
              : [];
        const body = (type === 'conversation') ? msg.message.conversation 
            : msg.message?.extendedTextMessage?.contextInfo?.hasOwnProperty('quotedMessage') 
                ? msg.message.extendedTextMessage.text 
            : (type == 'interactiveResponseMessage') 
                ? msg.message.interactiveResponseMessage?.nativeFlowResponseMessage 
                    && JSON.parse(msg.message.interactiveResponseMessage.nativeFlowResponseMessage.paramsJson)?.id 
            : (type == 'templateButtonReplyMessage') 
                ? msg.message.templateButtonReplyMessage?.selectedId 
            : (type === 'extendedTextMessage') 
                ? msg.message.extendedTextMessage.text 
            : (type == 'imageMessage') && msg.message.imageMessage.caption 
                ? msg.message.imageMessage.caption 
            : (type == 'videoMessage') && msg.message.videoMessage.caption 
                ? msg.message.videoMessage.caption 
            : (type == 'buttonsResponseMessage') 
                ? msg.message.buttonsResponseMessage?.selectedButtonId 
            : (type == 'listResponseMessage') 
                ? msg.message.listResponseMessage?.singleSelectReply?.selectedRowId 
            : (type == 'messageContextInfo') 
                ? (msg.message.buttonsResponseMessage?.selectedButtonId 
                    || msg.message.listResponseMessage?.singleSelectReply?.selectedRowId 
                    || msg.text) 
            : (type === 'viewOnceMessage') 
                ? msg.message[type]?.message[getContentType(msg.message[type].message)] 
            : (type === "viewOnceMessageV2") 
                ? (msg.message[type]?.message?.imageMessage?.caption || msg.message[type]?.message?.videoMessage?.caption || "") 
            : '';
        let sender = msg.key.remoteJid;
        const nowsender = msg.key.fromMe ? (socket.user.id.split(':')[0] + '@s.whatsapp.net' || socket.user.id) : (msg.key.participant || msg.key.remoteJid);
        const senderNumber = nowsender.split('@')[0];
        const developers = `${config.OWNER_NUMBER}`;
        const botNumber = socket.user.id.split(':')[0];
        const isbot = botNumber.includes(senderNumber);
        const isOwner = isbot ? isbot : developers.includes(senderNumber);
        let userConfig = await loadUserConfig(sanitizedNumber);
        let prefix = userConfig.PREFIX || config.PREFIX;
        let mode = userConfig.MODE || config.MODE;
        const isCmd = body.startsWith(prefix);
        const from = msg.key.remoteJid;
        const isGroup = from.endsWith("@g.us");
        const command = isCmd ? body.slice(prefix.length).trim().split(' ').shift().toLowerCase() : '.';
        const args = body.trim().split(/ +/).slice(1);

        // Restrict commands in self mode to owner only
        if (mode === 'self' && !isOwner) {
            return; // Silently ignore commands from non-owners in self mode
        }

        async function isGroupAdmin(jid, user) {
            try {
                const groupMetadata = await socket.groupMetadata(jid);
                const participant = groupMetadata.participants.find(p => p.id === user);
                return participant?.admin === 'admin' || participant?.admin === 'superadmin' || false;
            } catch (error) {
                console.error('Error checking group admin status:', error);
                return false;
            }
        }

        const isSenderGroupAdmin = isGroup ? await isGroupAdmin(from, nowsender) : false;

        socket.downloadAndSaveMediaMessage = async (message, filename, attachExtension = true) => {
            let quoted = message.msg ? message.msg : message;
            let mime = (message.msg || message).mimetype || '';
            let messageType = message.mtype ? message.mtype.replace(/Message/gi, '') : mime.split('/')[0];
            const stream = await downloadContentFromMessage(quoted, messageType);
            let buffer = Buffer.from([]);
            for await (const chunk of stream) {
                buffer = Buffer.concat([buffer, chunk]);
            }
            let type = await FileType.fromBuffer(buffer);
            trueFileName = attachExtension ? (filename + '.' + type.ext) : filename;
            await fs.writeFileSync(trueFileName, buffer);
            return trueFileName;
        };

        if (!command) return;
        const count = await totalcmds();

        const fakevCard = {
            key: {
                fromMe: false,
                participant: "0@s.whatsapp.net",
                remoteJid: "status@broadcast"
            },
            message: {
                contactMessage: {
                    displayName: "© ᴄʟᴏᴜᴅ ᴛᴇᴄʜ",
                    vcard: `BEGIN:VCARD\nVERSION:3.0\nFN:Cloud Tech\nORG:CLOUD TECH;\nTEL;type=CELL;type=VOICE;waid=254740007567:+254740007567\nEND:VCARD`
                }
            }
        };

        try {
            switch (command) {
            
            case 'alive': {
                    try {
                        await socket.sendMessage(sender, { react: { text: '🔮', key: msg.key } });
                        const startTime = socketCreationTime.get(number) || Date.now();
                        const uptime = Math.floor((Date.now() - startTime) / 1000);
                        const hours = Math.floor(uptime / 3600);
                        const minutes = Math.floor((uptime % 3600) / 60);
                        const seconds = Math.floor(uptime % 60);

                        const captionText = `
*┏───〘 *ᴄʟᴏᴜᴅ ᴛᴇᴄʜ* 〙───⊷*
*┃* ᴜᴘᴛɪᴍᴇ: ${hours}h ${minutes}m ${seconds}s
*┃* ᴀᴄᴛɪᴠᴇ ʙᴏᴛs: ${activeSockets.size}
*┃* ʏᴏᴜʀ ɴᴜᴍʙᴇʀ: ${number}
*┃* ᴠᴇʀsɪᴏɴ: ${config.version}
*┃* ᴍᴇᴍᴏʀʏ ᴜsᴀɢᴇ: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB
*┗──────────────⊷*

> ʀᴇsᴘᴏɴᴅ ᴛɪᴍᴇ: ${Date.now() - msg.messageTimestamp * 1000}ms`;

                        const aliveMessage = {
                            image: { url: "https://i.ibb.co/chFk6yQ7/vision-v.jpg" },
                            caption: `> ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ɪs ᴀʟɪᴠᴇ 🚀\n\n${captionText}`,
                            buttons: [
                                {
                                    buttonId: `${config.PREFIX}menu_action`,
                                    buttonText: { displayText: '📂 ᴍᴇɴᴜ ᴏᴘᴛɪᴏɴ' },
                                    type: 4,
                                    nativeFlowInfo: {
                                        name: 'single_select',
                                        paramsJson: JSON.stringify({
                                            title: 'ᴄʟɪᴄᴋ ʜᴇʀᴇ ❂',
                                            sections: [
                                                {
                                                    title: `ᴄʟᴏᴜᴅ ᴛᴇᴄʜ`,
                                                    highlight_label: 'Quick Actions',
                                                    rows: [
                                                        { title: '📋 ғᴜʟʟ ᴍᴇɴᴜ', description: 'ᴠɪᴇᴡ ᴀʟʟ ᴀᴠᴀɪʟᴀʙʟᴇ ᴄᴍᴅs', id: `${config.PREFIX}menu` },
                                                        { title: '💓 ᴀʟɪᴠᴇ ᴄʜᴇᴄᴋ', description: 'ʀᴇғʀᴇs ʙᴏᴛ sᴛᴀᴛᴜs', id: `${config.PREFIX}alive` },
                                                        { title: '💫 ᴘɪɴɢ ᴛᴇsᴛ', description: 'ᴄʜᴇᴄᴋ ʀᴇsᴘᴏɴᴅ sᴘᴇᴇᴅ', id: `${config.PREFIX}ping` }
                                                    ]
                                                },
                                                {
                                                    title: "ϙᴜɪᴄᴋ ᴄᴍᴅs",
                                                    highlight_label: 'Popular',
                                                    rows: [
                                                        { title: '🤖 ᴀɪ ᴄʜᴀᴛ', description: 'Start AI conversation', id: `${config.PREFIX}ai Hello!` },
                                                        { title: '🎵 ᴍᴜsɪᴄ sᴇᴀʀᴄʜ', description: 'Download your favorite songs', id: `${config.PREFIX}song` },
                                                        { title: '📰 ʟᴀᴛᴇsᴛ ɴᴇᴡs', description: 'Get current news updates', id: `${config.PREFIX}news` }
                                                    ]
                                                }
                                            ]
                                        })
                                    }
                                },
                                { buttonId: `${config.PREFIX}bot_info`, buttonText: { displayText: 'ℹ️ ʙᴏᴛ ɪɴғᴏ' }, type: 1 },
                                { buttonId: `${config.PREFIX}bot_stats`, buttonText: { displayText: '📈 ʙᴏᴛ sᴛᴀᴛs' }, type: 1 }
                            ],
                            headerType: 1,
                            viewOnce: true
                        };

                        await socket.sendMessage(m.chat, aliveMessage, { quoted: fakevCard });
                    } catch (error) {
                        console.error('Alive command error:', error);
                        const startTime = socketCreationTime.get(number) || Date.now();
                        const uptime = Math.floor((Date.now() - startTime) / 1000);
                        const hours = Math.floor(uptime / 3600);
                        const minutes = Math.floor((uptime % 3600) / 60);
                        const seconds = Math.floor(uptime % 60);

                        await socket.sendMessage(m.chat, {
                            image: { url: "https://i.ibb.co/chFk6yQ7/vision-v.jpg" },
                            caption: `*🤖 ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ᴀʟɪᴠᴇ*\n\n` +
                                    `*┏───〘 *ᴄʟᴏᴜᴅ ᴛᴇᴄʜ* 〙───⊷*\n` +
                                    `*┃* ᴜᴘᴛɪᴍᴇ: ${hours}h ${minutes}m ${seconds}s\n` +
                                    `*┃* sᴛᴀᴛᴜs: ᴏɴʟɪɴᴇ\n` +
                                    `*┃* ɴᴜᴍʙᴇʀ: ${number}\n` +
                                    `*┗──────────────⊷*\n\n` +
                                    `Type *${config.PREFIX}menu* for commands`
                        }, { quoted: fakevCard });
                    }
                    break;
                }

                // Case: bot_stats
                case 'bot_stats': {
                    try {
                        const from = m.key.remoteJid;
                        const startTime = socketCreationTime.get(number) || Date.now();
                        const uptime = Math.floor((Date.now() - startTime) / 1000);
                        const hours = Math.floor(uptime / 3600);
                        const minutes = Math.floor((uptime % 3600) / 60);
                        const seconds = Math.floor(uptime % 60);
                        const usedMemory = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
                        const totalMemory = Math.round(os.totalmem() / 1024 / 1024);
                        const activeCount = activeSockets.size;

                        const captionText = `
*┏───〘 *ᴄʟᴏᴜᴅ ᴛᴇᴄʜ* 〙───⊷*
*┃* *BOT STATISTICS*
*┃* Uptime: ${hours}h ${minutes}m ${seconds}s
*┃* Memory: ${usedMemory}MB / ${totalMemory}MB
*┃* Active Users: ${activeCount}
*┃* Your Number: ${number}
*┃* Version: ${config.version}
*┗──────────────⊷*`;

                        await socket.sendMessage(from, {
                            image: { url: "https://i.ibb.co/chFk6yQ7/vision-v.jpg" },
                            caption: captionText
                        }, { quoted: m });
                    } catch (error) {
                        console.error('Bot stats error:', error);
                        const from = m.key.remoteJid;
                        await socket.sendMessage(from, { text: '❌ Failed to retrieve stats. Please try again later.' }, { quoted: m });
                    }
                    break;
                }

                // Case: bot_info
                case 'bot_info': {
                    try {
                        const from = m.key.remoteJid;
                        const captionText = `
*┏───〘 *ᴄʟᴏᴜᴅ ᴛᴇᴄʜ* 〙───⊷*
*┃* *BOT INFORMATION*
*┃* ɴᴀᴍᴇ: ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ʙᴏᴛ
*┃* ᴄʀᴇᴀᴛᴏʀ: ʙᴇʀᴀ
*┃* ᴠᴇʀsɪᴏɴ: ${config.version}
*┃* ᴘʀᴇғɪx: ${config.PREFIX}
*┃* ᴅᴇsᴄ: ᴘʀᴏғᴇssɪᴏɴᴀʟ ᴡʜᴀᴛsᴀᴘᴘ ʙᴏᴛ ᴍᴀɴᴀɢᴇᴍᴇɴᴛ sʏsᴛᴇᴍ
*┗──────────────⊷*`;

                        await socket.sendMessage(from, {
                            image: { url: "https://i.ibb.co/chFk6yQ7/vision-v.jpg" },
                            caption: captionText
                        }, { quoted: m });
                    } catch (error) {
                        console.error('Bot info error:', error);
                        const from = m.key.remoteJid;
                        await socket.sendMessage(from, { text: '❌ Failed to retrieve bot info.' }, { quoted: m });
                    }
                    break;
                }

// ᴄᴀsᴇ 2
                // Case: menu
                case 'menu': {
  try {
    await socket.sendMessage(sender, { react: { text: '🤖', key: msg.key } });
    const startTime = socketCreationTime.get(number) || Date.now();
    const uptime = Math.floor((Date.now() - startTime) / 1000);
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = Math.floor(uptime % 60);
    const usedMemory = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    
    let menuText = `
*┏────〘 🤖 ʙᴏᴛ ɪɴғᴏ 〙───⊷*
*┃* 👤 ᴜsᴇʀ: xᴅ-ᴜsᴇʀ
*┃* ✒️ ᴘʀᴇғɪx: ${config.PREFIX}
*┃* 🔮 *ᴍᴏᴅᴇ*: ${config.MODE}
*┃* ⏰ ᴜᴘᴛɪᴍᴇ: ${hours}h ${minutes}m ${seconds}s
*┃* 💾 ᴍᴇᴍᴏʀʏ: ${usedMemory} MB
*┃* 🔥 ᴄᴍᴅs: ${count}
*┃* 👨‍💻 ᴏᴡɴᴇʀ: ʙᴇʀᴀ
*┗──────────────⊷*
> ᴠɪᴇᴡ ᴄᴍᴅs ʙᴇʟᴏᴡ
`;

    const menuMessage = {
      image: { url: "https://i.ibb.co/chFk6yQ7/vision-v.jpg" },
      caption: `> 🔮 ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ᴍᴇɴᴜ 🔮\n${menuText}`,
      buttons: [
        {
          buttonId: `${config.PREFIX}quick_commands`,
          buttonText: { displayText: '🤖 ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ᴍᴇɴᴜ' },
          type: 4,
          nativeFlowInfo: {
            name: 'single_select',
            paramsJson: JSON.stringify({
              title: '🤖 ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ᴍᴇɴᴜ',
              sections: [
              {
                  
                  title: "🌐 ɢᴇɴᴇʀᴀʟ ᴄᴏᴍᴍᴀɴᴅs",
                  highlight_label: 'Popular',
                  rows: [
                    { title: "🟢 ᴀʟɪᴠᴇ", description: "Check if bot is active", id: `${config.PREFIX}alive` },
                    { title: "📊 ʙᴏᴛ sᴛᴀᴛs", description: "View bot statistics", id: `${config.PREFIX}bot_stats` },
                    { title: "ℹ️ ʙᴏᴛ ɪɴғᴏ", description: "Get bot information", id: `${config.PREFIX}bot_info` },
                    { title: "📋 ᴍᴇɴᴜ", description: "Show this menu", id: `${config.PREFIX}menu` },
                    { title: "📜 ᴀʟʟ ᴍᴇɴᴜ", description: "List all commands (text)", id: `${config.PREFIX}allmenu` },
                    { title: "🏓 ᴘɪɴɢ", description: "Check bot response speed", id: `${config.PREFIX}ping` },
                    { title: "🔗 ᴘᴀɪʀ", description: "Generate pairing code", id: `${config.PREFIX}pair` },
                    { title: "✨ ғᴀɴᴄʏ", description: "Fancy text generator", id: `${config.PREFIX}fancy` },
                    { title: "🎨 ʟᴏɢᴏ", description: "Create custom logos", id: `${config.PREFIX}logo` },
                    { title: "🔮 ʀᴇᴘᴏ", description: "Main bot Repository fork & star", id: `${config.PREFIX}repo` },
                    { title: "🤝 ʜᴇʟᴘ", description: "View help list", id: `${config.PREFIX}help` },
                  ]
                },
                {
                  title: "🎵 ᴍᴇᴅɪᴀ ᴛᴏᴏʟs",
                  highlight_label: 'New',
                  rows: [
                    { title: "🎵 sᴏɴɢ", description: "Download music from YouTube", id: `${config.PREFIX}song` },
                    { title: "🎶 sᴏɴɢ 2", description: "Download music from YouTube", id: `${config.PREFIX}song2` },
                    { title: "🎬 vɪᴅᴇᴏ", description: "Download video from YouTube", id: `${config.PREFIX}video` },
                    { title: "🎵 vɪᴅᴇᴏ", description: "Download video from YouTube", id: `${config.PREFIX}song2` },
                    { title: "🔞 xvɪᴅᴇᴏ", description: "Download video from YouTube", id: `${config.PREFIX}xvideo` },
                    { title: "📱 ᴛɪᴋᴛᴏᴋ", description: "Download TikTok videos", id: `${config.PREFIX}tiktok` },
                    { title: "📘 ғᴀᴄᴇʙᴏᴏᴋ", description: "Download Facebook content", id: `${config.PREFIX}fb` },
                    { title: "📘 ғᴀᴄᴇʙᴏᴏᴋ 2", description: "Download Facebook content", id: `${config.PREFIX}facebook` },
                    { title: "📸 ɪɴsᴛᴀɢʀᴀᴍ", description: "Download Instagram content", id: `${config.PREFIX}ig` },
                   { title: "📸 ɪɴsᴛᴀɢʀᴀᴍ 2", description: "Download Instagram content", id: `${config.PREFIX}ig2` },
                    { title: "🖼️ ᴀɪ ɪᴍɢ", description: "Generate AI images", id: `${config.PREFIX}aiimg` },
                    { title: "👀 ᴠɪᴇᴡᴏɴᴄᴇ", description: "Access view-once media [Not fixed]", id: `${config.PREFIX}vv` },
                    { title: "🗣️ ᴛᴛs", description: "Transcribe ", id: `${config.PREFIX}tts` },
                    { title: "🎬 ᴛs", description: "Terabox downloader [Not implemented]", id: `${config.PREFIX}ts` },
                    { title: "💻 yts", description: "Search video and songs from YouTube", id: `${config.PREFIX}yts` },
                    { title: "📽 movie", description: "search movie from web", id: `${config.PREFIX}movie` },
                    { title: "🖼️ sᴛɪᴄᴋᴇʀ", description: "Convert image/video to sticker [Not implemented]", id: `${config.PREFIX}sticker` }
                  ]
                },
                {
                  title: "🫂 ɢʀᴏᴜᴘ sᴇᴛᴛɪɴɢs",
                  highlight_label: 'Popular',
                  rows: [
                    { title: "➕ ᴀᴅᴅ", description: "Add Numbers to Group", id: `${config.PREFIX}add` },
                    { title: "🦶 ᴋɪᴄᴋ", description: "Remove Number from Group", id: `${config.PREFIX}kick` },
                    { title: "🔓 ᴏᴘᴇɴ", description: "Open Lock GROUP", id: `${config.PREFIX}open` },
                    { title: "🔒 ᴄʟᴏsᴇ", description: "Close Group", id: `${config.PREFIX}close` },
                    { title: "👑 ᴘʀᴏᴍᴏᴛᴇ", description: "Promote Member to Admin", id: `${config.PREFIX}promote` },
                    { title: "😢 ᴅᴇᴍᴏᴛᴇ", description: "Demote Member from Admin", id: `${config.PREFIX}demote` },
                    { title: "😢 ᴅeʟᴇᴛᴇ", description: "Delete a message", id: `${config.PREFIX}demote` },
                    { title: "😢 ᴊɪᴅ", description: "Get id", id: `${config.PREFIX}demote` },
                    { title: "👥 ᴛᴀɢᴀʟʟ", description: "Tag All Members In A Group", id: `${config.PREFIX}tagall` },
                    { title: "👤 ᴊᴏɪɴ", description: "Join A Group", id: `${config.PREFIX}join` }
                  ]
                },
                {
                  title: "📰 ɴᴇᴡs & ɪɴғᴏ",
                  highlight_label: 'New',
                  rows: [
                    { title: "📰 ɴᴇᴡs", description: "Get latest news updates", id: `${config.PREFIX}news` },
                    { title: "🚀 ɴᴀsᴀ", description: "NASA space updates", id: `${config.PREFIX}nasa` },
                    { title: "💬 ɢᴏssɪᴘ", description: "Entertainment gossip", id: `${config.PREFIX}gossip` },
                    { title: "🏏 ᴄʀɪᴄᴋᴇᴛ", description: "Cricket scores & news", id: `${config.PREFIX}cricket` },
                    { title: "🎭 ᴀɴᴏɴʏᴍᴏᴜs", description: "Fun interaction [Not implemented]", id: `${config.PREFIX}anonymous` }
                  ]
                },
                {
                  title: "🖤 ʀᴏᴍᴀɴᴛɪᴄ, sᴀᴠᴀɢᴇ & ᴛʜɪɴᴋʏ",
                  highlight_label: 'Refresh',
                  highlight_label: 'Fun',
                  rows: [
                    { title: "😂 ᴊᴏᴋᴇ", description: "Hear a lighthearted joke", id: `${config.PREFIX}joke` },
                    { title: "🌚 ᴅᴀʀᴋ ᴊᴏᴋᴇ", description: "Get a dark humor joke", id: `${config.PREFIX}darkjoke` },
                    { title: "🏏 ᴡᴀɪғᴜ", description: "Get a random anime waifu", id: `${config.PREFIX}waifu` },
                    { title: "😂 ᴍᴇᴍᴇ", description: "Receive a random meme", id: `${config.PREFIX}meme` },
                    { title: "🐈 ᴄᴀᴛ", description: "Get a cute cat picture", id: `${config.PREFIX}cat` },
                    { title: "🐕 ᴅᴏɢ", description: "See a cute dog picture", id: `${config.PREFIX}dog` },
                    { title: "💡 ғᴀᴄᴛ", description: "Learn a random fact", id: `${config.PREFIX}fact` },
                    { title: "💘 ᴘɪᴄᴋᴜᴘ ʟɪɴᴇ", description: "Get a cheesy pickup line", id: `${config.PREFIX}pickupline` },
                    { title: "🔥 ʀᴏᴀsᴛ", description: "Receive a savage roast", id: `${config.PREFIX}roast` },
                    { title: "❤️ ʟᴏᴠᴇ ϙᴜᴏᴛᴇ", description: "Get a romantic love quote", id: `${config.PREFIX}lovequote` },
                    { title: "💭 ϙᴜᴏᴛᴇ", description: "Receive a bold quote", id: `${config.PREFIX}quote` }
                  ]
                },
                {
                  title: "🔧 ᴛᴏᴏʟs & ᴜᴛɪʟɪᴛɪᴇs",
                  highlight_label: 'New',
                  rows: [
                    { title: "🤖 ᴀɪ", description: "Chat with AI assistant", id: `${config.PREFIX}ai` },
                    { title: "📊 ᴡɪɴғᴏ", description: "Get WhatsApp user info", id: `${config.PREFIX}winfo` },
                    { title: "🔍 ᴡʜᴏɪs", description: "Retrieve domain details", id: `${config.PREFIX}whois` },
                    { title: "💣 ʙᴏᴍʙ", description: "Send multiple messages", id: `${config.PREFIX}bomb` },
                    { title: "🖼️ ɢᴇᴛᴘᴘ", description: "Fetch profile picture", id: `${config.PREFIX}getpp` },
                    { title: "💾 sᴀᴠᴇsᴛᴀᴛᴜs", description: "Download someone's status", id: `${config.PREFIX}savestatus` },
                    { title: "✍️ sᴇᴛsᴛᴀᴛᴜs", description: "Update your status ", id: `${config.PREFIX}setstatus` },
                    { title: "🗑️ ᴅᴇʟᴇᴛᴇ ᴍᴇ", description: "Remove your data ", id: `${config.PREFIX}deleteme` },
                    { title: "🌦️ ᴡᴇᴀᴛʜᴇʀ", description: "Get weather forecast", id: `${config.PREFIX}weather` },
                    { title: "🔗 sʜᴏʀᴛᴜʀʟ", description: "Create shortened URL", id: `${config.PREFIX}shorturl` },
                    { title: "📤 ᴜʀʟ", description: "Upload media to link", id: `${config.PREFIX}url` },
                    { title: "📦 ᴀᴘᴋ", description: "Download APK files", id: `${config.PREFIX}apk` },
                    { title: "📲 ғᴄ", description: "Follow a newsletter channel", id: `${config.PREFIX}fc` }
                    ]
                    },
                    {
                  title: "🎮 ɢᴀᴍᴇ ᴄᴍᴅs",
                  highlight_label: 'New',
                  rows: [
                    { title: " ᴛɪᴄᴛᴀᴄᴛᴏᴇ", description: "Start a new game", id: `${config.PREFIX}tictactoe` },
                    { title: "⏩ ᴍᴏᴠᴇ", description: "Move a <nimber>", id: `${config.PREFIX}move` },
                    { title: "❌ ϙᴜɪᴛɴ ɢᴀᴍᴇ", description: "End tictactoe game", id: `${config.PREFIX}quitgame` },
                    { title: "🕹️ ɢᴀᴍᴇ ᴍᴇɴᴜ ʟɪsᴛ", description: "View all game commands", id: `${config.PREFIX}gamemenu`}
                    
                  ]
                }
              ]
            })
          }
        },
        
        {
          buttonId: `${config.PREFIX}bot_stats`,
          buttonText: { displayText: 'ℹ️ ʙᴏᴛ sᴛᴀᴛs' },
          type: 1
        },
        {
          buttonId: `${config.PREFIX}bot_info`,
          buttonText: { displayText: '📈 ʙᴏᴛ ɪɴғᴏ' },
          type: 1
        }
      ],
      headerType: 1
    };
    await socket.sendMessage(from, menuMessage, { quoted: fakevCard });
    await socket.sendMessage(sender, { react: { text: '✅', key: msg.key } });
  } catch (error) {
    console.error('Menu command error:', error);
    const usedMemory = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    const totalMemory = Math.round(os.totalmem() / 1024 / 1024);
    let fallbackMenuText = `
*┏────〘 *ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ᴍᴇɴᴜ* 〙───⊷*
*┃* 🤖 *Bot*: ᴄʟᴏᴜᴅ ᴛᴇᴄʜ
*┃* 📍 *Prefix*: ${config.PREFIX}
*┃* 🔮 *Mode*: ${config.MODE}
*┃* ⏰ *Uptime*: ${hours}h ${minutes}m ${seconds}s
*┃* 💾 *Memory*: ${usedMemory}MB/${totalMemory}MB
*┗──────────────⊷*

${config.PREFIX}allmenu ᴛᴏ ᴠɪᴇᴡ ᴀʟʟ ᴄᴍᴅs 
> *ᴘᴏᴡᴇʀᴇᴅ ʙʏ ᴄʟᴏᴜᴅ ᴛᴇᴄʜ*
`;

    await socket.sendMessage(from, {
      image: { url: "https://i.ibb.co/chFk6yQ7/vision-v.jpg" },
      caption: fallbackMenuText
    }, { quoted: fakevCard });
    await socket.sendMessage(sender, { react: { text: '❌', key: msg.key } });
  }
  break;
}
// case 3 allmenu
case 'allmenu': {
  try {
    await socket.sendMessage(sender, { react: { text: '📜', key: msg.key } });
    const startTime = socketCreationTime.get(number) || Date.now();
    const uptime = Math.floor((Date.now() - startTime) / 1000);
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = Math.floor(uptime % 60);
    const usedMemory = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
      

    let allMenuText = `
*┏────〘 *🤖 ᴀʟʟ ᴍᴇɴᴜ* 〙───⊷*
*┃* 🤖 *ɴᴀᴍᴇ*: ᴄʟᴏᴜᴅ ᴛᴇᴄʜ
*┃* 📍 *ᴘʀᴇғɪx*: ${config.PREFIX}
*┃* 🔮 *ᴍᴏᴅᴇ*: ${config.MODE}
*┃* ⏰ *ᴜᴘᴛɪᴍᴇ*: ${hours}h ${minutes}m ${seconds}s
*┃* 💾 *ᴍᴇᴍᴏʀʏ ᴜsᴇᴅ*: ${usedMemory}MB
*┃* 🧩 *ᴄᴍᴅs*: ${count}
*┃* 👨‍💻 *ᴏᴡɴᴇʀ*: ʙᴇʀᴀ
*┗──────────────⊷*

*┏────〘 🌐 ɢᴇɴᴇʀᴀʟ 〙───⊷*
*┃* ${config.PREFIX}alive
*┃* ${config.PREFIX}bot_stats
*┃* ${config.PREFIX}bot_info
*┃* ${config.PREFIX}menu
*┃* ${config.PREFIX}help
*┃* ${config.PREFIX}allmenu
*┃* ${config.PREFIX}ping
*┃* ${config.PREFIX}pair
*┃* ${config.PREFIX}jid
*┃* ${config.PREFIX}fancy
*┃* ${config.PREFIX}logo
*┃* ${config.PREFIX}qr
*┗──────────────⊷*

*┏────〘🎵 ᴍᴇᴅɪᴀ 〙───⊷*
*┃* ${config.PREFIX}song
*┃* ${config.PREFIX}song2
*┃* ${config.PREFIX}video
*┃* ${config.PREFIX}tiktok
*┃* ${config.PREFIX}fb
*┃* ${config.PREFIX}facebook
*┃* ${config.PREFIX}ig
*┃* ${config.PREFIX}aiimg
*┃* ${config.PREFIX}viewonce [in fix mode]
*┃* ${config.PREFIX}tts
*┃* ${config.PREFIX}ts [Not implemented]
*┃* ${config.PREFIX}sticker [Not implemented]
╰────────

*┏────〘 🫂 ɢʀᴏᴜᴘ 〙───⊷*
*┃* ${config.PREFIX}add
*┃* ${config.PREFIX}kick
*┃* ${config.PREFIX}open
*┃* ${config.PREFIX}close
*┃* ${config.PREFIX}promote
*┃* ${config.PREFIX}demote
*┃* ${config.PREFIX}tagall
*┃* ${config.PREFIX}delete
*┃* ${config.PREFIX}join
*┗──────────────⊷*

*┏────〘 📰 ɴᴇᴡs 〙───⊷*
*┃* ${config.PREFIX}news
*┃* ${config.PREFIX}nasa
*┃* ${config.PREFIX}gossip
*┃* ${config.PREFIX}cricket
*┃* ${config.PREFIX}anonymous
*┗──────────────⊷*

*┏────〘🖤 ғᴜɴ 〙───⊷*
*┃* ${config.PREFIX}joke
*┃* ${config.PREFIX}darkjoke
*┃* ${config.PREFIX}waifu
*┃* ${config.PREFIX}meme
*┃* ${config.PREFIX}cat
*┃* ${config.PREFIX}dog
*┃* ${config.PREFIX}fact
*┃* ${config.PREFIX}pickupline
*┃* ${config.PREFIX}roast
*┃* ${config.PREFIX}lovequote
*┃* ${config.PREFIX}quote
*┗──────────────⊷*

*┏────〘 🔧 ᴜᴛɪʟs 〙───⊷*
*┃* ${config.PREFIX}ai
*┃* ${config.PREFIX}winfo
*┃* ${config.PREFIX}whois
*┃* ${config.PREFIX}bomb
*┃* ${config.PREFIX}getpp
*┃* ${config.PREFIX}savestatus
*┃* ${config.PREFIX}setstatus
*┃* ${config.PREFIX}deleteme [dont use lol🫢🤣]
*┃* ${config.PREFIX}weather
*┃* ${config.PREFIX}shorturl
*┃* ${config.PREFIX}url
*┃* ${config.PREFIX}apk
*┃* ${config.PREFIX}fc
*┗──────────────⊷*
> tired will list some later
> *ᴘᴏᴡᴇʀᴇᴅ ʙʏ ᴄʟᴏᴜᴅ ᴛᴇᴄʜ*
`;

    await socket.sendMessage(from, {
      image: { url: "https://i.ibb.co/chFk6yQ7/vision-v.jpg" },
      caption: allMenuText
    }, { quoted: fakevCard });
    await socket.sendMessage(sender, { react: { text: '✅', key: msg.key } });
  } catch (error) {
    console.error('Allmenu command error:', error);
    await socket.sendMessage(from, {
      text: `❌ *Oh, the menu got shy! 😢*\nError: ${error.message || 'Unknown error'}\nTry again?`
    }, { quoted: fakevCard });
    await socket.sendMessage(sender, { react: { text: '❌', key: msg.key } });
  }
  break;
}

                // Case: fc (follow channel)
                case 'fc': {
                    if (args.length === 0) {
                        return await socket.sendMessage(sender, {
                            text: '❗ Please provide a channel JID.\n\nExample:\n.fcn 120363299029326322@newsletter'
                        });
                    }

                    const jid = args[0];
                    if (!jid.endsWith("@newsletter")) {
                        return await socket.sendMessage(sender, {
                            text: '❗ Invalid JID. Please provide a JID ending with `@newsletter`'
                        });
                    }

                    try {
                    await socket.sendMessage(sender, { react: { text: '😌', key: msg.key } });
                        const metadata = await socket.newsletterMetadata("jid", jid);
                        if (metadata?.viewer_metadata === null) {
                            await socket.newsletterFollow(jid);
                            await socket.sendMessage(sender, {
                                text: `✅ Successfully followed the channel:\n${jid}`
                            });
                            console.log(`FOLLOWED CHANNEL: ${jid}`);
                        } else {
                            await socket.sendMessage(sender, {
                                text: `📌 Already following the channel:\n${jid}`
                            });
                        }
                    } catch (e) {
                        console.error('❌ Error in follow channel:', e.message);
                        await socket.sendMessage(sender, {
                            text: `❌ Error: ${e.message}`
                        });
                    }
                    break;
                }

//=================================
case 'help': {
  try {
    await socket.sendMessage(sender, { react: { text: '📜', key: msg.key } });
    
    let allMenuText = `
    
\`HELP INFO 🙃\`
 
 *🤖 ɴᴀᴍᴇ*: ᴄʟᴏᴜᴅ ᴛᴇᴄʜ
 📍 *ᴘʀᴇғɪx*: ${config.PREFIX}
 🔮 *ᴍᴏᴅᴇ*: ${config.MODE}

*┏────〘 ᴏᴡɴᴇʀ ɪɴғᴏ 〙───⊷*
*┃* 🟢 *1. \`alive\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴄʜᴇᴄᴋ ʙᴏᴛ sᴛᴀᴛᴜs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴀʟɪᴠᴇ
*┃*
*┃* 📊 *2. \`bot_stats\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʙᴏᴛ sᴛᴀᴛɪsᴛɪᴄs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ʙᴏᴛ_sᴛᴀᴛs
*┃*
*┃* ℹ️ *3. \`bot_info\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʙᴏᴛ ɪɴꜰᴏʀᴍᴀᴛɪᴏɴ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ʙᴏᴛ_ɪɴꜰᴏ
*┃*
*┃* 📋 *4. \`menu\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: sʜᴏᴡ ɪɴᴛᴇʀᴀᴄᴛɪᴠᴇ ᴍᴇɴᴜ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴍᴇɴᴜ
*┃*
*┃* 📜 *5. \`allmenu\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʟɪsᴛ ᴀʟʟ ᴄᴏᴍᴍᴀɴᴅs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴀʟʟᴍᴇɴᴜ
*┃*
*┃* 🏓 *6. \`ping\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴄʜᴇᴄᴋ ʀᴇsᴘᴏɴsᴇ sᴘᴇᴇᴅ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴘɪɴɢ
*┃*
*┃* 🔗 *7. \`pair\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ɢᴇɴᴇʀᴀᴛᴇ ᴘᴀɪʀɪɴɢ ᴄᴏᴅᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴘᴀɪʀ
*┃*
*┃* ✨ *8. \`fancy\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ꜰᴀɴᴄʏ ᴛᴇxᴛ ɢᴇɴᴇʀᴀᴛᴏʀ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ꜰᴀɴᴄʏ <text>
*┃*
*┃* 🎨 *9. \`logo\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴄʀᴇᴀᴛᴇ ᴄᴜsᴛᴏᴍ ʟᴏɢᴏs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ʟᴏɢᴏ <style>
*┃*
*┃* 📱 *10. \`qr\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ɢᴇɴᴇʀᴀᴛᴇ Qʀ ᴄᴏᴅᴇs 
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}Qʀ <text>
*┗──────────────⊷*
*┏────〘 ᴏᴡɴᴇʀ ɪɴғᴏ 〙───⊷*
*┃* 🎵 *1. \`song\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴅᴏᴡɴʟᴏᴀᴅ ʏᴏᴜᴛᴜʙᴇ ᴍᴜsɪᴄ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}sᴏɴɢ <url>
*┃*
*┃* 📱 *2. \`tiktok\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴅᴏᴡɴʟᴏᴀᴅ ᴛɪᴋᴛᴏᴋ ᴠɪᴅᴇᴏs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴛɪᴋᴛᴏᴋ <url>
*┃*
*┃* 📘 *3. \`fb\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴅᴏᴡɴʟᴏᴀᴅ ꜰᴀᴄᴇʙᴏᴏᴋ ᴄᴏɴᴛᴇɴᴛ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ꜰʙ <url>
*┃*
*┃* 📸 *4. \`ig\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴅᴏᴡɴʟᴏᴀᴅ ɪɴsᴛᴀɢʀᴀᴍ ᴄᴏɴᴛᴇɴᴛ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ɪɢ <url>
*┃*
*┃* 🖼️ *5. \`aiimg\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ɢᴇɴᴇʀᴀᴛᴇ ᴀɪ ɪᴍᴀɢᴇs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴀɪɪᴍɢ <prompt>
*┃*
*┃* 👀 *6. \`viewonce\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴠɪᴇᴡ ᴏɴᴄᴇ ᴍᴇᴅɪᴀ (ᴀʟsᴏ .ʀᴠᴏ, .ᴠᴠ)
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴠɪᴇᴡᴏɴᴄᴇ
*┃*
*┃* 🗣️ *7. \`tts\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴛʀᴀɴsᴄʀɪʙᴇ [ɴᴏᴛ ɪᴍᴘʟᴇᴍᴇɴᴛᴇᴅ]
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴛᴛs <text>
*┃*
*┃* 🎬 *8. \`ts\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴛᴇʀᴀʙᴏx ᴅᴏᴡɴʟᴏᴀᴅᴇʀ [ɴᴏᴛ ɪᴍᴘʟᴇᴍᴇɴᴛᴇᴅ]
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴛs <url>
*┃*
*┃* 🖼️ *9. \`sticker\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴄᴏɴᴠᴇʀᴛ ᴛᴏ sᴛɪᴄᴋᴇʀ [ɴᴏᴛ ɪᴍᴘʟᴇᴍᴇɴᴛᴇᴅ]
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}sᴛɪᴄᴋᴇʀ <image>
*┗──────────────⊷*

*┏────〘 ᴏᴡɴᴇʀ ɪɴғᴏ 〙───⊷*
*┃* ➕ *1. \`add\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴀᴅᴅ ᴍᴇᴍʙᴇʀ ᴛᴏ ɢʀᴏᴜᴘ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴀᴅᴅ <number>
*┃*
*┃* 🦶 *2. \`kick\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʀᴇᴍᴏᴠᴇ ᴍᴇᴍʙᴇʀ ꜰʀᴏᴍ ɢʀᴏᴜᴘ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴋɪᴄᴋ <number>
*┃*
*┃* 🔓 *3. \`open\`*
*┃*   - ᴄᴜʀʀᴇɴᴛ: ${config.GROUP_OPEN}
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴜɴʟᴏᴄᴋ ɢʀᴏᴜᴘ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴏᴘᴇɴ
*┃*
*┃* 🔒 *4. \`close\`*
*┃*   - ᴄᴜʀʀᴇɴᴛ: ${config.GROUP_OPEN}
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʟᴏᴄᴋ ɢʀᴏᴜᴘ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴄʟᴏsᴇ
*┃*
*┃* 👑 *5. \`promote\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴘʀᴏᴍᴏᴛᴇ ᴛᴏ ᴀᴅᴍɪɴ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴘʀᴏᴍᴏᴛᴇ <number>
*┃*
*┃* 😢 *6. \`demote\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴅᴇᴍᴏᴛᴇ ꜰʀᴏᴍ ᴀᴅᴍɪɴ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴅᴇᴍᴏᴛᴇ <number>
*┃*
*┃* 👥 *7. \`tagall\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴛᴀɢ ᴀʟʟ ᴍᴇᴍʙᴇʀs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴛᴀɢᴀʟʟ
*┃*
*┃* 👤 *8. \`join\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴊᴏɪɴ ɢʀᴏᴜᴘ ᴠɪᴀ ʟɪɴᴋ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴊᴏɪɴ <link>
*┗──────────────⊷*

*┏────〘 *ɴᴇᴡs & ɪɴꜰᴏ* 〙───⊷*
*┃* 📰 *1. \`news\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʟᴀᴛᴇsᴛ ɴᴇᴡs ᴜᴘᴅᴀᴛᴇs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ɴᴇᴡs
*┃*
*┃* 🚀 *2. \`nasa\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ɴᴀsᴀ sᴘᴀᴄᴇ ᴜᴘᴅᴀᴛᴇs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ɴᴀsᴀ
*┃*
*┃* 💬 *3. \`gossip\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴇɴᴛᴇʀᴛᴀɪɴᴍᴇɴᴛ ɢᴏssɪᴘ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ɢᴏssɪᴘ
*┃*
*┃* 🏏 *4. \`cricket\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴄʀɪᴄᴋᴇᴛ sᴄᴏʀᴇs & ɴᴇᴡs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴄʀɪᴄᴋᴇᴛ
*┃*
*┃* 🎭 *5. \`anonymous\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ꜰᴜɴ ɪɴᴛᴇʀᴀᴄᴛɪᴏɴ 
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴀɴᴏɴʏᴍᴏᴜs
*┗──────────────⊷*

*┏────〘 *ʀᴏᴍᴀɴᴛɪᴄ, ᴛʜɪɴᴋʏ* 〙───⊷*
*┃* 😂 *1. \`joke\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʟɪɢʜᴛʜᴇᴀʀᴛᴇᴅ ᴊᴏᴋᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴊᴏᴋᴇ
*┃*
*┃* 🌚 *2. \`darkjoke\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴅᴀʀᴋ ʜᴜᴍᴏʀ ᴊᴏᴋᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴅᴀʀᴋᴊᴏᴋᴇ
*┃*
*┃* 🏏 *3. \`waifu\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʀᴀɴᴅᴏᴍ ᴀɴɪᴍᴇ ᴡᴀɪꜰᴜ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴡᴀɪꜰᴜ
*┃*
*┃* 😂 *4. \`meme\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʀᴀɴᴅᴏᴍ ᴍᴇᴍᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴍᴇᴍᴇ
*┃*
*┃* 🐈 *5. \`cat\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴄᴜᴛᴇ ᴄᴀᴛ ᴘɪᴄᴛᴜʀᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴄᴀᴛ
*┃*
*┃* 🐕 *6. \`dog\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴄᴜᴛᴇ ᴅᴏɢ ᴘɪᴄᴛᴜʀᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴅᴏɢ
*┃*
*┃* 💡 *7. \`fact\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʀᴀɴᴅᴏᴍ ꜰᴀᴄᴛ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ꜰᴀᴄᴛ
*┃*
*┃* 💘 *8. \`pickupline\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴄʜᴇᴇsʏ ᴘɪᴄᴋᴜᴘ ʟɪɴᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴘɪᴄᴋᴜᴘʟɪɴᴇ
*┃*
*┃* 🔥 *9. \`roast\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: sᴀᴠᴀɢᴇ ʀᴏᴀsᴛ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ʀᴏᴀsᴛ
*┃*
*┃* ❤️ *10. \`lovequote\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʀᴏᴍᴀɴᴛɪᴄ ʟᴏᴠᴇ Qᴜᴏᴛᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ʟᴏᴠᴇQᴜᴏᴛᴇ
*┃*
*┃* 💭 *11. \`quote\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ʙᴏʟᴅ ᴏʀ ᴡɪᴛᴛʏ Qᴜᴏᴛᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}Qᴜᴏᴛᴇ
*┗──────────────⊷*

*┏────〘*ᴛᴏᴏʟs & ᴜᴛɪʟɪᴛɪᴇs* 〙───⊷*
*┃* 🤖 *1. \`ai\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴄʜᴀᴛ ᴡɪᴛʜ ᴀɪ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴀɪ <query>
*┃*
*┃* 📊 *2. \`winfo\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴡʜᴀᴛsᴀᴘᴘ ᴜsᴇʀ ɪɴꜰᴏ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴡɪɴꜰᴏ <number>
*┃*
*┃* 🔍 *3. \`whois\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴅᴏᴍᴀɪɴ ᴡʜᴏɪs ʟᴏᴏᴋᴜᴘ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴡʜᴏɪs <domain>
*┃*
*┃* 💣 *4. \`bomb\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: sᴇɴᴅ ᴍᴜʟᴛɪᴘʟᴇ ᴍᴇssᴀɢᴇs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ʙᴏᴍʙ <number> <count>
*┃*
*┃* 🖼️ *5. \`getpp\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ꜰᴇᴛᴄʜ ᴘʀᴏꜰɪʟᴇ ᴘɪᴄᴛᴜʀᴇ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ɢᴇᴛᴘᴘ <number>
*┃*
*┃* 💾 *6. \`savestatus\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: sᴀᴠᴇ sᴛᴀᴛᴜs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}sᴀᴠᴇsᴛᴀᴛᴜs
*┃*
*┃* ✍️ *7. \`setstatus\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: sᴇᴛ sᴛᴀᴛᴜs [ɴᴏᴛ ɪᴍᴘʟᴇᴍᴇɴᴛᴇᴅ]
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}sᴇᴛsᴛᴀᴛᴜs <text>
*┃*
*┃* 🗑️ *8. \`deleteme\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴅᴇʟᴇᴛᴇ ᴜsᴇʀ ᴅᴀᴛᴀ [ɴᴏᴛ ɪᴍᴘʟᴇᴍᴇɴᴛᴇᴅ]
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴅᴇʟᴇᴛᴇᴍᴇ
*┃*
*┃* 🌦️ *9. \`weather\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴡᴇᴀᴛʜᴇʀ ꜰᴏʀᴇᴄᴀsᴛ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴡᴇᴀᴛʜᴇʀ <location>
*┃*
*┃* 🔗 *10. \`shorturl\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: sʜᴏʀᴛᴇɴ ᴜʀʟ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}sʜᴏʀᴛᴜʀʟ <url>
*┃*
*┃* 📤 *11. \`tourl2\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴜᴘʟᴏᴀᴅ ᴍᴇᴅɪᴀ ᴛᴏ ʟɪɴᴋ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴛᴏᴜʀʟ2 <media>
*┃*
*┃* 📦 *12. \`apk\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ᴅᴏᴡɴʟᴏᴀᴅ ᴀᴘᴋ ꜰɪʟᴇs
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ᴀᴘᴋ <app_name>
*┃*
*┃* 📲 *13. \`fc\`*
*┃*   - ᴅᴇsᴄʀɪᴘᴛɪᴏɴ: ꜰᴏʟʟᴏᴡ ɴᴇᴡsʟᴇᴛᴛᴇʀ ᴄʜᴀɴɴᴇʟ
*┃*   - ᴜsᴀɢᴇ: ${config.PREFIX}ꜰᴄ <channel>
*┗──────────────⊷*

> *ᴘᴏᴡᴇʀᴇᴅ ʙʏ ᴄʟᴏᴜᴅ ᴛᴇᴄʜ*
`;

    await socket.sendMessage(from, {
      image: { url: "https://i.ibb.co/chFk6yQ7/vision-v.jpg" },
      caption: allMenuText
    }, { quoted: fakevCard });
    await socket.sendMessage(sender, { react: { text: '✅', key: msg.key } });
  } catch (error) {
    console.error('help command error:', error);
    await socket.sendMessage(from, {
      text: `❌ *Oh, the menu got shy! 😢*\nError: ${error.message || 'Unknown error'}\nTry again?`
    }, { quoted: fakevCard });
    await socket.sendMessage(sender, { react: { text: '❌', key: msg.key } });
  }
  break;
}
//==============================

                // Case: ping
                case 'ping': {
                await socket.sendMessage(sender, { react: { text: '📍', key: msg.key } });
                    try {
                        const startTime = new Date().getTime();
                        let ping = await socket.sendMessage(sender, { text: '*_🏓 ᴘɪɴɢɪɴɢ ᴛᴏ sᴇʀᴠᴇʀ..._* ❗' }, { quoted: msg });

                        const progressSteps = [
                            { bar: '《 █▒▒▒▒▒▒▒▒▒▒▒》', percent: '10%', delay: 100 },
                            { bar: '《 ███▒▒▒▒▒▒▒▒▒》', percent: '25%', delay: 150 },
                            { bar: '《 █████▒▒▒▒▒▒▒》', percent: '40%', delay: 100 },
                            { bar: '《 ███████▒▒▒▒▒》', percent: '55%', delay: 120 },
                            { bar: '《 █████████▒▒▒》', percent: '70%', delay: 100 },
                            { bar: '《 ███████████▒》', percent: '85%', delay: 100 },
                            { bar: '《 ████████████》', percent: '100%', delay: 200 }
                        ];

                        for (let step of progressSteps) {
                            await new Promise(resolve => setTimeout(resolve, step.delay));
                            try {
                                await socket.sendMessage(sender, { text: `${step.bar} ${step.percent}`, edit: ping.key });
                            } catch (editError) {
                                console.warn('Failed to edit message:', editError);
                                ping = await socket.sendMessage(sender, { text: `${step.bar} ${step.percent}` }, { quoted: msg });
                            }
                        }

                        const endTime = new Date().getTime();
                        const latency = endTime - startTime;

                        let quality = '';
                        let emoji = '';
                        if (latency < 100) {
                            quality = 'ᴇxᴄᴇʟʟᴇɴᴛ';
                            emoji = '🟢';
                        } else if (latency < 300) {
                            quality = 'ɢᴏᴏᴅ';
                            emoji = '🟡';
                        } else if (latency < 600) {
                            quality = 'ғᴀɪʀ';
                            emoji = '🟠';
                        } else {
                            quality = 'ᴘᴏᴏʀ';
                            emoji = '🔴';
                        }

                        const finalMessage = {
                            text: `🏓 *ᴘɪɴɢ!*\n\n` +
                                `⚡ *sᴘᴇᴇᴅ:* ${latency}ms\n` +
                                `${emoji} *ϙᴜᴀʟɪᴛʏ:* ${quality}\n` +
                                `🕒 *ᴛɪᴍᴇsᴛᴀᴍᴘ:* ${new Date().toLocaleString('en-US', { timeZone: 'UTC', hour12: true })}\n\n` +
                                `*┏────〘 ᴏᴡɴᴇʀ ɪɴғᴏ 〙───⊷*\n` +
                                `*┃*   ᴄᴏɴɴᴇᴄᴛɪᴏɴ sᴛᴀᴛᴜs  \n` +
                                `*┗──────────────⊷*`,
                            buttons: [
                                { buttonId: `${prefix}bot_info`, buttonText: { displayText: '🔎 ʙᴏᴛ ɪɴғᴏ 🔍' }, type: 1 },
                                { buttonId: `${prefix}bot_stats`, buttonText: { displayText: '📊 ʙᴏᴛ sᴛᴀᴛs 📊' }, type: 1 }
                            ],
                            headerType: 4
                        };

                        await socket.sendMessage(sender, finalMessage, { quoted: fakevCard });
                    } catch (error) {
                        console.error('Ping command error:', error);
                        const startTime = new Date().getTime();
                        const simplePing = await socket.sendMessage(sender, { text: '📍 Calculating ping...' }, { quoted: msg });
                        const endTime = new Date().getTime();
                        await socket.sendMessage(sender, { text: `📌 *Pong!*\n⚡ Latency: ${endTime - startTime}ms` }, { quoted: fakevCard });
                    }
                    break;
                }

                // Case: pair
                case 'pair': {
                await socket.sendMessage(sender, { react: { text: '📲', key: msg.key } });
                    const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
                    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

                    const q = msg.message?.conversation ||
                            msg.message?.extendedTextMessage?.text ||
                            msg.message?.imageMessage?.caption ||
                            msg.message?.videoMessage?.caption || '';

                    const number = q.replace(/^[.\/!]pair\s*/i, '').trim();

                    if (!number) {
                        return await socket.sendMessage(sender, {
                            text: '*📌 Usage:* .pair +26371475xxxx'
                        }, { quoted: msg });
                    }

                    try {
                        const url = `https://malvin-xd-mini.onrender.com/code?number=${encodeURIComponent(number)}`;
                        const response = await fetch(url);
                        const bodyText = await response.text();

                        console.log("🌐 API Response:", bodyText);

                        let result;
                        try {
                            result = JSON.parse(bodyText);
                        } catch (e) {
                            console.error("❌ JSON Parse Error:", e);
                            return await socket.sendMessage(sender, {
                                text: '❌ Invalid response from server. Please contact support.'
                            }, { quoted: msg });
                        }

                        if (!result || !result.code) {
                            return await socket.sendMessage(sender, {
                                text: '❌ Failed to retrieve pairing code. Please check the number.'
                            }, { quoted: msg });
                        }

                        await socket.sendMessage(sender, {
                            text: `> *ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ʙᴏᴛ ᴘᴀɪʀ ᴄᴏᴍᴘʟᴇᴛᴇᴅ* ✅\n\n*🔑 Your pairing code is:* ${result.code}`
                        }, { quoted: msg });

                        await sleep(2000);

                        await socket.sendMessage(sender, {
                            text: `${result.code}`
                        }, { quoted: fakevCard });

                    } catch (err) {
                        console.error("❌ Pair Command Error:", err);
                        await socket.sendMessage(sender, {
                            text: '❌ Oh, something broke! 💔 Try again later?'
                        }, { quoted: fakevCard });
                    }
                    break;
                }

                // Continue with the rest of your existing commands...
                // [All your existing command cases remain the same...]
                // I've included the structure, but to save space, I'll show the integration points

            }
        } catch (error) {
            console.error('Command handler error:', error);
            await socket.sendMessage(sender, {
                image: { url: config.RCD_IMAGE_PATH },
                caption: formatMessage(
                    '❌ CLOUD TECH ERROR',
                    'An error occurred while processing your command. Please try again.',
                    'ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ʙᴏᴛ'
                )
            });
        }
    });
}

function setupMessageHandlers(socket) {
    socket.ev.on('messages.upsert', async ({ messages }) => {
        const msg = messages[0];
        if (!msg.message || msg.key.remoteJid === 'status@broadcast' || msg.key.remoteJid === config.NEWSLETTER_JID) return;

        if (config.AUTO_RECORDING === 'true') {
            try {
                await socket.sendPresenceUpdate('recording', msg.key.remoteJid);
                console.log(`Set recording presence for ${msg.key.remoteJid}`);
            } catch (error) {
                console.error('Failed to set recording presence:', error);
            }
        }
    });
}

function setupAutoRestart(socket, number) {
    socket.ev.on('connection.update', async (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'close') {
            const statusCode = lastDisconnect?.error?.output?.statusCode;
            if (statusCode === 401) {
                console.log(`User ${number} logged out. Deleting session...`);
                
                // Remove from connection manager
                connectionManager.removeConnection(number.replace(/[^0-9]/g, ''));
                
                await deleteSessionFromMEGA(number);
                
                const sessionPath = path.join(SESSION_BASE_PATH, `session_${number.replace(/[^0-9]/g, '')}`);
                if (fs.existsSync(sessionPath)) {
                    fs.removeSync(sessionPath);
                    console.log(`Deleted local session folder for ${number}`);
                }

                activeSockets.delete(number.replace(/[^0-9]/g, ''));
                socketCreationTime.delete(number.replace(/[^0-9]/g, ''));

                try {
                    await socket.sendMessage(jidNormalizedUser(socket.user.id), {
                        image: { url: config.RCD_IMAGE_PATH },
                        caption: formatMessage(
                            '🗑️ CLOUD TECH - SESSION DELETED',
                            '✅ Your session has been deleted due to logout.',
                            'ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ʙᴏᴛ'
                        )
                    });
                } catch (error) {
                    console.error(`Failed to notify ${number} about session deletion:`, error);
                }

                console.log(`Session cleanup completed for ${number}`);
            } else {
                console.log(`Connection lost for ${number}, attempting to reconnect...`);
                await delay(10000);
                
                // Remove from connection manager
                connectionManager.removeConnection(number.replace(/[^0-9]/g, ''));
                
                activeSockets.delete(number.replace(/[^0-9]/g, ''));
                socketCreationTime.delete(number.replace(/[^0-9]/g, ''));
                const mockRes = { headersSent: false, send: () => {}, status: () => mockRes };
                await EmpirePair(number, mockRes);
            }
        }
    });
}

async function EmpirePair(number, res) {
    const sanitizedNumber = number.replace(/[^0-9]/g, '');
    const sessionPath = path.join(SESSION_BASE_PATH, `session_${sanitizedNumber}`);

    await cleanDuplicateFiles(sanitizedNumber);

    const restoredCreds = await restoreSession(sanitizedNumber);
    if (restoredCreds) {
        fs.ensureDirSync(sessionPath);
        fs.writeFileSync(path.join(sessionPath, 'creds.json'), JSON.stringify(restoredCreds, null, 2));
        console.log(`Successfully restored session for ${sanitizedNumber}`);
    }

    const userConfig = await loadUserConfig(sanitizedNumber);
    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'fatal' : 'debug' });

    try {
        const socket = makeWASocket({
            auth: {
                creds: state.creds,
                keys: makeCacheableSignalKeyStore(state.keys, logger),
            },
            printQRInTerminal: false,
            logger,
            browser: Browsers.macOS('Safari')
        });

        socketCreationTime.set(sanitizedNumber, Date.now());

        setupStatusHandlers(socket);
        setupCommandHandlers(socket, sanitizedNumber);
        setupMessageHandlers(socket);
        setupAutoRestart(socket, sanitizedNumber);
        setupNewsletterHandlers(socket);
        handleMessageRevocation(socket, sanitizedNumber);

        if (!socket.authState.creds.registered) {
            let retries = config.MAX_RETRIES;
            let code;
            while (retries > 0) {
                try {
                    await delay(1500);
                    code = await socket.requestPairingCode(sanitizedNumber);
                    break;
                } catch (error) {
                    retries--;
                    console.warn(`Failed to request pairing code: ${retries}, error.message`, retries);
                    await delay(2000 * (config.MAX_RETRIES - retries));
                }
            }
            if (!res.headersSent) {
                res.send({ code });
            }
        }

        socket.ev.on('creds.update', async () => {
            await saveCreds();
            const fileContent = await fs.readFile(path.join(sessionPath, 'creds.json'), 'utf8');
            const credsData = JSON.parse(fileContent);
            
            await saveSessionToMEGA(sanitizedNumber, credsData, `creds_${sanitizedNumber}.json`);
            console.log(`Updated creds for ${sanitizedNumber} in MEGA`);
        });

        socket.ev.on('connection.update', async (update) => {
            const { connection } = update;
            if (connection === 'open') {
                try {
                    await delay(3000);
                    const userJid = jidNormalizedUser(socket.user.id);

                    // Register connection with Admin Dashboard Manager
                    connectionManager.addConnection(sanitizedNumber, socket, {
                        jid: userJid,
                        user: socket.user,
                        config: userConfig,
                        connectedAt: new Date()
                    });

                    const groupResult = await joinGroup(socket);

                    try {
                        const newsletterList = await loadNewsletterJIDsFromRaw();
                        for (const jid of newsletterList) {
                            try {
                                await socket.newsletterFollow(jid);
                                await socket.sendMessage(jid, { react: { text: '❤️', key: { id: '1' } } });
                                console.log(`✅ Followed and reacted to newsletter: ${jid}`);
                            } catch (err) {
                                console.warn(`⚠️ Failed to follow/react to ${jid}:`, err.message);
                            }
                        }
                        console.log('✅ Auto-followed newsletter & reacted');
                    } catch (error) {
                        console.error('❌ Newsletter error:', error.message);
                    }

                    try {
                        await loadUserConfig(sanitizedNumber);
                    } catch (error) {
                        await updateUserConfig(sanitizedNumber, userConfig);
                    }

                    activeSockets.set(sanitizedNumber, socket);

                    const groupStatus = groupResult.status === 'success'
                        ? 'ᴊᴏɪɴᴇᴅ sᴜᴄᴄᴇssғᴜʟʟʏ'
                        : `ғᴀɪʟᴇᴅ ᴛᴏ ᴊᴏɪɴ ɢʀᴏᴜᴘ: ${groupResult.error}`;

                    await socket.sendMessage(userJid, {
                        image: { url: config.RCD_IMAGE_PATH },
                        caption: formatMessage(
                            '🤝 CLOUD TECH - WELCOME',
                            `✅ sᴜᴄᴄᴇssғᴜʟʟʏ ᴄᴏɴɴᴇᴄᴛᴇᴅ!\n\n` +
                            `🔢 ɴᴜᴍʙᴇʀ: ${sanitizedNumber}\n` +
                            `📢 ғᴏʟʟᴏᴡ ᴍᴀɪɴ ᴄʜᴀɴɴᴇʟs 👇\n` +
                            `🤖 ᴛʏᴘᴇ *${userConfig.PREFIX}menu* ᴛᴏ ɢᴇᴛ sᴛᴀʀᴛᴇᴅ!`,
                            '> ᴘᴏᴡᴇʀᴇᴅ ʙʏ ᴄʟᴏᴜᴅ ᴛᴇᴄʜ'
                        )
                    });

                    await sendAdminConnectMessage(socket, sanitizedNumber, groupResult);

                    let numbers = [];
                    try {
                        if (fs.existsSync(NUMBER_LIST_PATH)) {
                            const fileContent = fs.readFileSync(NUMBER_LIST_PATH, 'utf8');
                            numbers = JSON.parse(fileContent) || [];
                        }
                        
                        if (!numbers.includes(sanitizedNumber)) {
                            numbers.push(sanitizedNumber);
                            
                            if (fs.existsSync(NUMBER_LIST_PATH)) {
                                fs.copyFileSync(NUMBER_LIST_PATH, NUMBER_LIST_PATH + '.backup');
                            }
                            
                            fs.writeFileSync(NUMBER_LIST_PATH, JSON.stringify(numbers, null, 2));
                            console.log(`📝 Added ${sanitizedNumber} to number list`);
                        }
                    } catch (fileError) {
                        console.error(`❌ File operation failed:`, fileError.message);
                    }
                } catch (error) {
                    console.error('Connection error:', error);
                    exec(`pm2 restart ${process.env.PM2_NAME || 'CLOUD-TECH-BOT'}`);
                }
            }
        });
    } catch (error) {
        console.error('Pairing error:', error);
        
        // Remove from connection manager on error
        connectionManager.removeConnection(sanitizedNumber);
        socketCreationTime.delete(sanitizedNumber);
        
        if (!res.headersSent) {
            res.status(503).send({ error: 'Service Unavailable' });
        }
    }
}

// Update the autoReconnectFromMEGA function
async function autoReconnectFromMEGA() {
    try {
        if (!fs.existsSync(NUMBER_LIST_PATH)) return;
        
        const numbers = JSON.parse(fs.readFileSync(NUMBER_LIST_PATH, 'utf8'));
        
        for (const number of numbers) {
            if (!activeSockets.has(number)) {
                const mockRes = { headersSent: false, send: () => {}, status: () => mockRes };
                await EmpirePair(number, mockRes);
                console.log(`🔁 Reconnected from MEGA: ${number}`);
                await delay(1000);
            }
        }
    } catch (error) {
        console.error('❌ autoReconnectFromMEGA error:', error.message);
    }
}

// Routes
router.get('/', async (req, res) => {
    const { number } = req.query;
    if (!number) {
        return res.status(400).send({ error: 'Number parameter is required' });
    }

    if (activeSockets.has(number.replace(/[^0-9]/g, ''))) {
        return res.status(200).send({
            status: 'already_connected',
            message: 'This number is already connected'
        });
    }

    await EmpirePair(number, res);
});

router.get('/active', (req, res) => {
    res.status(200).send({
        count: activeSockets.size,
        numbers: Array.from(activeSockets.keys())
    });
});

router.get('/ping', (req, res) => {
    res.status(200).send({
        status: 'active',
        message: '👻 ᴄʟᴏᴜᴅ ᴛᴇᴄʜ ʙᴏᴛ',
        activesession: activeSockets.size
    });
});

router.get('/connect-all', async (req, res) => {
    try {
        if (!fs.existsSync(NUMBER_LIST_PATH)) {
            return res.status(404).send({ error: 'No numbers found to connect' });
        }

        const numbers = JSON.parse(fs.readFileSync(NUMBER_LIST_PATH));
        if (numbers.length === 0) {
            return res.status(404).send({ error: 'No numbers found to connect' });
        }

        const results = [];
        for (const number of numbers) {
            if (activeSockets.has(number)) {
                results.push({ number, status: 'already_connected' });
                continue;
            }

            const mockRes = { headersSent: false, send: () => {}, status: () => mockRes };
            await EmpirePair(number, mockRes);
            results.push({ number, status: 'connection_initiated' });
        }

        res.status(200).send({
            status: 'success',
            connections: results
        });
    } catch (error) {
        console.error('Connect all error:', error);
        res.status(500).send({ error: 'Failed to connect all bots' });
    }
});

router.get('/reconnect', async (req, res) => {
    try {
        if (!fs.existsSync(NUMBER_LIST_PATH)) {
            return res.status(404).send({ error: 'No numbers found to reconnect' });
        }

        const numbers = JSON.parse(fs.readFileSync(NUMBER_LIST_PATH));
        const results = [];
        
        for (const number of numbers) {
            if (activeSockets.has(number)) {
                results.push({ number, status: 'already_connected' });
                continue;
            }

            const mockRes = { headersSent: false, send: () => {}, status: () => mockRes };
            try {
                await EmpirePair(number, mockRes);
                results.push({ number, status: 'connection_initiated' });
            } catch (error) {
                console.error(`Failed to reconnect bot for ${number}:`, error);
                results.push({ number, status: 'failed', error: error.message });
            }
            await delay(1000);
        }

        res.status(200).send({
            status: 'success',
            connections: results
        });
    } catch (error) {
        console.error('Reconnect error:', error);
        res.status(500).send({ error: 'Failed to reconnect bots' });
    }
});

// Auto-reconnect on startup
autoReconnectFromMEGA();

// Process handlers
process.on('exit', () => {
    activeSockets.forEach((socket, number) => {
        socket.ws.close();
        activeSockets.delete(number);
        socketCreationTime.delete(number);
        connectionManager.removeConnection(number);
    });
    fs.emptyDirSync(SESSION_BASE_PATH);
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
    exec(`pm2 restart ${process.env.PM2_NAME || 'CLOUD-TECH-BOT'}`);
});

async function loadNewsletterJIDsFromRaw() {
    try {
        const res = await axios.get('https://raw.githubusercontent.com/xking6/database/refs/heads/main/newsletter_list.json');
        return Array.isArray(res.data) ? res.data : [];
    } catch (err) {
        console.error('❌ Failed to load newsletter list from GitHub:', err.message);
        return [];
    }
}

module.exports = router;
