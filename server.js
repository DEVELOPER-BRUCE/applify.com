// server.js
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'applify-secret-key-2024';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// PayHero Configuration
const PAYHERO_CONFIG = {
    API_KEY: 'v38BZT005Qx8NYjYnCIT',
    API_SECRET: 'PCTduYGpbr2r9Ae6xWt9YBUrQgNQhrMS5vRIUunw',
    ACCOUNT_ID: '3342',
    BASIC_AUTH: 'Basic djM0QlPUTzA1UXg4TllqWW5DSVQ6UENUZHVZR3BicjJyOUFlNnhXdDlZQlVyUWdOUWhyTVM1dlJJVVXUdW==',
    BASE_URL: 'https://api.payhero.co.ke/v3/stk/push'
};

// SendGrid Configuration
const SENDGRID_CONFIG = {
    API_KEY: process.env.SENDGRID_API_KEY,
    FROM_EMAIL: 'support@applify.com',
    FROM_NAME: 'Applify'
};

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/applify', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Database Models
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: String,
    createdAt: { type: Date, default: Date.now }
});

const AppSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    websiteUrl: { type: String, required: true },
    appName: { type: String, required: true },
    appIcon: String,
    appType: { type: String, enum: ['pwa', 'apk'], required: true },
    status: { type: String, enum: ['processing', 'completed', 'failed'], default: 'processing' },
    apkPath: String,
    pwaPath: String,
    orderId: { type: String, unique: true },
    paymentStatus: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' },
    paymentReference: String,
    amount: Number,
    createdAt: { type: Date, default: Date.now }
});

const PaymentSchema = new mongoose.Schema({
    orderId: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    appId: { type: mongoose.Schema.Types.ObjectId, ref: 'App' },
    phoneNumber: { type: String, required: true },
    amount: { type: Number, required: true },
    transactionId: String,
    merchantRequestId: String,
    checkoutRequestId: String,
    status: { type: String, enum: ['pending', 'success', 'failed', 'cancelled'], default: 'pending' },
    mpesaReceiptNumber: String,
    transactionDate: Date,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const App = mongoose.model('App', AppSchema);
const Payment = mongoose.model('Payment', PaymentSchema);

// Email Transporter
const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Utility Functions
const generateOrderId = () => {
    return 'APP' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
};

const validatePhoneNumber = (phone) => {
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.startsWith('254') && cleaned.length === 12) return cleaned;
    if (cleaned.startsWith('0') && cleaned.length === 10) return '254' + cleaned.substring(1);
    if (cleaned.startsWith('7') && cleaned.length === 9) return '254' + cleaned;
    return null;
};

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// PayHero STK Push Function
async function initiateSTKPush(phoneNumber, amount, orderId, description) {
    try {
        const payload = {
            phone: phoneNumber,
            amount: amount,
            reference: orderId,
            description: description,
            callback_url: `${process.env.BASE_URL || 'http://localhost:5000'}/api/payments/callback`
        };

        console.log('Initiating STK Push with payload:', payload);

        const response = await axios.post(PAYHERO_CONFIG.BASE_URL, payload, {
            headers: {
                'Authorization': PAYHERO_CONFIG.BASIC_AUTH,
                'Content-Type': 'application/json',
                'X-Account': PAYHERO_CONFIG.ACCOUNT_ID
            },
            timeout: 30000
        });

        console.log('PayHero API Response:', response.data);

        if (response.data && response.data.success) {
            return {
                success: true,
                transactionId: response.data.transaction_id,
                merchantRequestId: response.data.merchant_request_id,
                checkoutRequestId: response.data.checkout_request_id,
                responseDescription: response.data.response_description
            };
        } else {
            return {
                success: false,
                message: response.data.response_description || 'Failed to initiate payment'
            };
        }
    } catch (error) {
        console.error('PayHero STK Push Error:', error.response?.data || error.message);
        return {
            success: false,
            message: error.response?.data?.response_description || 'Payment service temporarily unavailable'
        };
    }
}

// APK Generation Function
async function generateAPK(websiteUrl, appName, appIcon = null) {
    return new Promise((resolve, reject) => {
        const appId = 'app' + Date.now();
        const outputDir = path.join(__dirname, 'apps', appId);
        
        // Create output directory
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        // For demo purposes, we'll create a simple APK generation simulation
        // In production, you would use tools like PWA Builder, Bubblewrap, or custom scripts
        
        const apkPath = path.join(outputDir, `${appName.replace(/\s+/g, '_')}.apk`);
        
        // Simulate APK generation process
        setTimeout(() => {
            // Create a dummy APK file for demonstration
            const apkContent = 'Simulated APK file for: ' + websiteUrl;
            fs.writeFileSync(apkPath, apkContent);
            
            resolve({
                success: true,
                apkPath: apkPath,
                downloadUrl: `/api/apps/download/${appId}`
            });
        }, 10000); // Simulate 10-second generation time
    });
}

// Send Email Function
async function sendEmail(to, subject, html) {
    try {
        const mailOptions = {
            from: `"Applify" <${SENDGRID_CONFIG.FROM_EMAIL}>`,
            to: to,
            subject: subject,
            html: html
        };

        await transporter.sendMail(mailOptions);
        console.log('Email sent to:', to);
        return true;
    } catch (error) {
        console.error('Email sending failed:', error);
        return false;
    }
}

// API Routes

// User Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        // Generate token
        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

        // Send welcome email
        const emailHtml = `
            <h2>Welcome to Applify!</h2>
            <p>Hello ${name},</p>
            <p>Your account has been successfully created. You can now start converting your websites to PWAs and APKs.</p>
            <p>Start by logging into your dashboard and converting your first website.</p>
            <br>
            <p>Best regards,<br>Applify Team</p>
        `;
        
        await sendEmail(email, 'Welcome to Applify!', emailHtml);

        res.json({
            success: true,
            message: 'User registered successfully',
            token,
            user: { id: user._id, name: user.name, email: user.email }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: { id: user._id, name: user.name, email: user.email }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Initiate APK Payment
app.post('/api/payments/initiate', authenticateToken, async (req, res) => {
    try {
        const { websiteUrl, appName, appIcon, phoneNumber } = req.body;
        const userId = req.user.userId;

        // Validate inputs
        if (!websiteUrl || !appName || !phoneNumber) {
            return res.status(400).json({ error: 'Website URL, app name, and phone number are required' });
        }

        // Validate phone number
        const formattedPhone = validatePhoneNumber(phoneNumber);
        if (!formattedPhone) {
            return res.status(400).json({ error: 'Invalid phone number format. Use 07XXXXXXXX or 2547XXXXXXXX' });
        }

        // Generate order ID
        const orderId = generateOrderId();
        const amount = 150; // 150 KSH

        // Create app record
        const app = new App({
            userId,
            websiteUrl,
            appName,
            appIcon,
            appType: 'apk',
            orderId,
            amount,
            status: 'processing',
            paymentStatus: 'pending'
        });

        await app.save();

        // Initiate STK Push
        const stkResult = await initiateSTKPush(formattedPhone, amount, orderId, `APK: ${appName}`);

        if (!stkResult.success) {
            await App.findByIdAndUpdate(app._id, { status: 'failed' });
            return res.status(400).json({ error: stkResult.message });
        }

        // Create payment record
        const payment = new Payment({
            orderId,
            userId,
            appId: app._id,
            phoneNumber: formattedPhone,
            amount,
            transactionId: stkResult.transactionId,
            merchantRequestId: stkResult.merchantRequestId,
            checkoutRequestId: stkResult.checkoutRequestId,
            status: 'pending'
        });

        await payment.save();

        // Update app with payment reference
        await App.findByIdAndUpdate(app._id, {
            paymentReference: stkResult.transactionId
        });

        res.json({
            success: true,
            message: 'Payment initiated successfully. Check your phone to complete payment.',
            orderId,
            transactionId: stkResult.transactionId,
            checkoutRequestId: stkResult.checkoutRequestId
        });

    } catch (error) {
        console.error('Payment initiation error:', error);
        res.status(500).json({ error: 'Failed to initiate payment' });
    }
});

// PayHero Callback Webhook
app.post('/api/payments/callback', async (req, res) => {
    try {
        console.log('Payment callback received:', req.body);

        const callbackData = req.body;
        
        // Find payment by checkout request ID or transaction ID
        const payment = await Payment.findOne({
            $or: [
                { checkoutRequestId: callbackData.CheckoutRequestID },
                { transactionId: callbackData.TransactionID }
            ]
        });

        if (!payment) {
            console.log('Payment not found for callback:', callbackData);
            return res.status(404).json({ error: 'Payment not found' });
        }

        // Update payment status based on callback
        if (callbackData.ResultCode === 0) {
            // Payment successful
            payment.status = 'success';
            payment.mpesaReceiptNumber = callbackData.MpesaReceiptNumber;
            payment.transactionDate = new Date();
            
            // Update app status
            await App.findOneAndUpdate(
                { orderId: payment.orderId },
                { 
                    paymentStatus: 'paid',
                    status: 'processing'
                }
            );

            // Start APK generation
            const app = await App.findOne({ orderId: payment.orderId });
            if (app) {
                generateAPK(app.websiteUrl, app.appName, app.appIcon)
                    .then(async (result) => {
                        if (result.success) {
                            await App.findByIdAndUpdate(app._id, {
                                status: 'completed',
                                apkPath: result.apkPath
                            });

                            // Send success email
                            const user = await User.findById(app.userId);
                            if (user) {
                                const emailHtml = `
                                    <h2>Your APK is Ready!</h2>
                                    <p>Hello ${user.name},</p>
                                    <p>Your Android APK for "${app.appName}" has been successfully generated.</p>
                                    <p>You can now download your APK from your Applify dashboard.</p>
                                    <p><strong>Website:</strong> ${app.websiteUrl}</p>
                                    <p><strong>App Name:</strong> ${app.appName}</p>
                                    <br>
                                    <a href="${process.env.BASE_URL || 'http://localhost:5000'}/dashboard" style="background-color: #4361ee; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px;">Download APK</a>
                                    <br><br>
                                    <p>Best regards,<br>Applify Team</p>
                                `;
                                
                                await sendEmail(user.email, 'Your APK is Ready!', emailHtml);
                            }
                        }
                    })
                    .catch(async (error) => {
                        console.error('APK generation failed:', error);
                        await App.findByIdAndUpdate(app._id, { status: 'failed' });
                        
                        const user = await User.findById(app.userId);
                        if (user) {
                            const emailHtml = `
                                <h2>APK Generation Failed</h2>
                                <p>Hello ${user.name},</p>
                                <p>We encountered an error while generating your APK for "${app.appName}".</p>
                                <p>Our team has been notified and will resolve this issue shortly.</p>
                                <p>If the problem persists, please contact our support team.</p>
                                <br>
                                <p>Best regards,<br>Applify Team</p>
                            `;
                            
                            await sendEmail(user.email, 'APK Generation Failed', emailHtml);
                        }
                    });
            }

        } else {
            // Payment failed
            payment.status = 'failed';
            await App.findOneAndUpdate(
                { orderId: payment.orderId },
                { 
                    paymentStatus: 'failed',
                    status: 'failed'
                }
            );

            // Send failure email
            const app = await App.findOne({ orderId: payment.orderId });
            if (app) {
                const user = await User.findById(app.userId);
                if (user) {
                    const emailHtml = `
                        <h2>Payment Failed</h2>
                        <p>Hello ${user.name},</p>
                        <p>Your payment for APK generation of "${app.appName}" has failed.</p>
                        <p>Please try again or contact support if the issue persists.</p>
                        <p>Error: ${callbackData.ResultDesc || 'Unknown error'}</p>
                        <br>
                        <p>Best regards,<br>Applify Team</p>
                    `;
                    
                    await sendEmail(user.email, 'Payment Failed', emailHtml);
                }
            }
        }

        await payment.save();

        res.json({ success: true, message: 'Callback processed successfully' });

    } catch (error) {
        console.error('Callback processing error:', error);
        res.status(500).json({ error: 'Failed to process callback' });
    }
});

// Check Payment Status
app.get('/api/payments/status/:orderId', authenticateToken, async (req, res) => {
    try {
        const { orderId } = req.params;

        const payment = await Payment.findOne({ orderId });
        if (!payment) {
            return res.status(404).json({ error: 'Payment not found' });
        }

        const app = await App.findOne({ orderId });

        res.json({
            success: true,
            payment: {
                status: payment.status,
                amount: payment.amount,
                phoneNumber: payment.phoneNumber,
                transactionId: payment.transactionId,
                mpesaReceiptNumber: payment.mpesaReceiptNumber,
                transactionDate: payment.transactionDate
            },
            app: app ? {
                status: app.status,
                appName: app.appName,
                websiteUrl: app.websiteUrl,
                downloadUrl: app.apkPath ? `/api/apps/download/${app._id}` : null
            } : null
        });

    } catch (error) {
        console.error('Payment status check error:', error);
        res.status(500).json({ error: 'Failed to check payment status' });
    }
});

// Get User Apps
app.get('/api/apps', authenticateToken, async (req, res) => {
    try {
        const apps = await App.find({ userId: req.user.userId }).sort({ createdAt: -1 });

        res.json({
            success: true,
            apps: apps.map(app => ({
                id: app._id,
                websiteUrl: app.websiteUrl,
                appName: app.appName,
                appType: app.appType,
                status: app.status,
                paymentStatus: app.paymentStatus,
                createdAt: app.createdAt,
                downloadUrl: app.apkPath ? `/api/apps/download/${app._id}` : null
            }))
        });

    } catch (error) {
        console.error('Get apps error:', error);
        res.status(500).json({ error: 'Failed to fetch apps' });
    }
});

// Download APK
app.get('/api/apps/download/:appId', authenticateToken, async (req, res) => {
    try {
        const { appId } = req.params;

        const app = await App.findOne({ _id: appId, userId: req.user.userId });
        if (!app) {
            return res.status(404).json({ error: 'App not found' });
        }

        if (!app.apkPath || !fs.existsSync(app.apkPath)) {
            return res.status(404).json({ error: 'APK file not found' });
        }

        const filename = `${app.appName.replace(/\s+/g, '_')}.apk`;
        res.download(app.apkPath, filename);

    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Failed to download APK' });
    }
});

// Create Free PWA
app.post('/api/apps/pwa', authenticateToken, async (req, res) => {
    try {
        const { websiteUrl, appName, appIcon } = req.body;
        const userId = req.user.userId;

        if (!websiteUrl || !appName) {
            return res.status(400).json({ error: 'Website URL and app name are required' });
        }

        const app = new App({
            userId,
            websiteUrl,
            appName,
            appIcon,
            appType: 'pwa',
            status: 'completed',
            paymentStatus: 'paid' // Free service
        });

        await app.save();

        // Generate PWA files (simplified for demo)
        const pwaData = {
            manifest: {
                name: appName,
                short_name: appName.substring(0, 12),
                start_url: websiteUrl,
                display: 'standalone',
                background_color: '#ffffff',
                theme_color: '#4361ee'
            },
            serviceWorker: `// Simplified service worker for ${websiteUrl}`
        };

        res.json({
            success: true,
            message: 'PWA created successfully',
            app: {
                id: app._id,
                websiteUrl: app.websiteUrl,
                appName: app.appName,
                appType: app.appType,
                status: app.status,
                pwaData: pwaData
            }
        });

    } catch (error) {
        console.error('PWA creation error:', error);
        res.status(500).json({ error: 'Failed to create PWA' });
    }
});

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Applify API is running',
        timestamp: new Date().toISOString()
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Applify server running on port ${PORT}`);
    console.log(`API Health Check: http://localhost:${PORT}/api/health`);
});
