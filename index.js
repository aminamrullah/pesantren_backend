require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const jwt = require('jsonwebtoken');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const xss = require('xss-clean');

const app = express();
const PORT = process.env.PORT || 5000;

// Serve public storage from Laravel (for images, etc)
app.use('/storage', express.static(path.join(__dirname, '../pesantren/storage/app/public')));

// ─── Xendit Configuration ───────────────────────────────────────────────────
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// Simple Xendit API caller with for-user-id support (XenPlatform)
async function xenditRequest(path, method = 'GET', body = null, forUserId = null) {
    const opts = {
        method,
        headers: {
            'Authorization': `Basic ${Buffer.from((process.env.XENDIT_SECRET_KEY || '') + ':').toString('base64')}`,
            'Content-Type': 'application/json'
        }
    };
    if (forUserId) opts.headers['for-user-id'] = forUserId;
    if (body) opts.body = JSON.stringify(body);

    const baseUrl = process.env.XENDIT_API_URL || 'https://api.xendit.co';
    const resp = await fetch(`${baseUrl}${path}`, opts);
    const data = await resp.json();
    if (!resp.ok) throw { status: resp.status, data };
    return data;
}

// ─── Verbose Logging ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
    console.log(`[DEBUG] ${new Date().toISOString()} - ${req.method} ${req.url} - Origin: ${req.get('origin')}`);
    next();
});

// ─── Security Middlewares ─────────────────────────────────────────────────────
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false
}));
app.use(hpp());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000, // Increased from 200 to 1000 for smoother dev/production experience
    message: 'Too many requests from this IP, please try again after 15 minutes.'
});
app.use('/api/', limiter);
app.use(xss());

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login attempts per windowMs
    message: { message: 'Terlalu banyak upaya login. Silakan coba lagi setelah 15 menit.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/login', loginLimiter);

const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : ['http://localhost:5173', 'http://localhost:5174'];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Origin not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json({ limit: '10kb' }));

// ─── Database Pool ────────────────────────────────────────────────────────────
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 50, // Increased for better concurrency
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10000
});

// ─── Notification Helper ──────────────────────────────────────────────────────
async function createNotification(userId, type, title, message, actionData = null) {
    try {
        await db.execute(`
            INSERT INTO user_notifications (user_id, type, title, message, action_data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
            [userId, type, title, message, actionData ? JSON.stringify(actionData) : null]);
    } catch (err) {
        console.error('[NOTIF ERROR]', err);
    }
}

// ─── JWT Auth Middleware ──────────────────────────────────────────────────────

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }
    if (!token) return res.status(401).json({ message: 'Akses ditolak. Token tidak ditemukan.' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Sesi berakhir. Silakan login kembali.' });
    }
};

// Internal API Key middleware (for admin/RFID terminal)
const protectAdmin = async (req, res, next) => {
    const apiKey = req.headers['x-admin-key'];
    if (apiKey && apiKey === process.env.ADMIN_API_KEY) return next();
    // Also allow JWT admin
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }
    if (!token) return res.status(401).json({ message: 'Admin access required.' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'Admin') return res.status(403).json({ message: 'Forbidden.' });
        req.user = decoded;
        next();
    } catch {
        return res.status(401).json({ message: 'Invalid token.' });
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/login', async (req, res) => {
    try {
        const { phone, password, app_type } = req.body;
        if (!phone || !password) return res.status(400).json({ message: 'Input tidak lengkap.' });

        const [users] = await db.execute(`
            SELECT u.*, r.name as role, t.is_tahfidz_teacher
            FROM users u
            LEFT JOIN model_has_roles mhr ON u.id = mhr.model_id AND mhr.model_type = ?
            LEFT JOIN roles r ON mhr.role_id = r.id
            LEFT JOIN teachers t ON u.id = t.user_id
            WHERE u.phone = ? OR u.email = ?`, ['App\\Models\\User', phone, phone]);

        if (users.length === 0) return res.status(401).json({ message: 'Nomor WhatsApp tidak terdaftar.' });

        const user = users[0];
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ message: 'Password salah.' });

        // Get all roles for access checking
        const userRoles = users.map(u => u.role).filter(Boolean);

        // Fetch students associated with this user's phone to verify if they are a wali santri
        const [students] = await db.execute(`
            SELECT s.*, w.id as wallet_id, c.name as classroom_name, d.name as dormitory_name, d.mushrif_name, dr.name as room_name, t.name as homeroom_teacher_name
            FROM students s
            LEFT JOIN wallets w ON s.id = w.student_id
            LEFT JOIN classrooms c ON s.classroom_id = c.id
            LEFT JOIN dormitories d ON s.dormitory_id = d.id
            LEFT JOIN dormitory_rooms dr ON s.dormitory_room_id = dr.id
            LEFT JOIN teachers t ON c.homeroom_teacher_id = t.id
            WHERE s.parent_phone = ?`, [user.phone || phone]);

        // Authorization Logic:
        const isWali = userRoles.includes('Wali');
        const isTeacher = userRoles.includes('Teacher');
        const isAdmin = userRoles.includes('Admin');
        const isParent = students.length > 0;

        // Restriction based on app_type
        if (app_type === 'walisantri') {
            if (!isWali && !isParent && !isAdmin) {
                return res.status(403).json({ message: 'Akses ditolak. Aplikasi ini hanya dapat diakses oleh Wali Santri.' });
            }
        } else if (app_type === 'guru') {
            if (!isTeacher && !isAdmin) {
                return res.status(403).json({ message: 'Akses ditolak. Aplikasi ini hanya dapat diakses oleh Guru.' });
            }
        }

        const token = jwt.sign(
            { id: user.id, phone: user.phone || phone, name: user.name, role: user.role, can_access_terminal: !!user.can_access_terminal },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRE || '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role,
                is_tahfidz_teacher: !!user.is_tahfidz_teacher,
                can_access_terminal: !!user.can_access_terminal
            },
            students
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  STUDENT ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/students/:id', protect, async (req, res) => {
    try {
        const id = req.params.id;
        const userPhone = req.user.phone;

        const [rows] = await db.execute(`
            SELECT s.*, c.name as classroom_name, d.name as dormitory_name, d.mushrif_name, dr.name as room_name, t.name as homeroom_teacher_name
            FROM students s
            LEFT JOIN classrooms c ON s.classroom_id = c.id
            LEFT JOIN dormitories d ON s.dormitory_id = d.id
            LEFT JOIN dormitory_rooms dr ON s.dormitory_room_id = dr.id
            LEFT JOIN teachers t ON c.homeroom_teacher_id = t.id
            WHERE s.id = ? AND s.parent_phone = ?`, [id, userPhone]);

        if (rows.length === 0) return res.status(403).json({ message: 'Data santri tidak ditemukan atau Anda tidak memiliki akses.' });

        const student = rows[0];

        // Fetch all related data
        const [bills] = await db.execute(`
            SELECT b.*, fc.name as category_name
            FROM bills b 
            LEFT JOIN fee_categories fc ON b.fee_category_id = fc.id 
            WHERE b.student_id = ? 
            ORDER BY b.due_date DESC`, [id]);
        student.bills = bills;

        const [tahfidz] = await db.execute('SELECT * FROM tahfidz_records WHERE student_id = ? ORDER BY date DESC', [id]);
        student.tahfidz = tahfidz;

        const [attendances] = await db.execute(`
            SELECT a.*, s.name as subject_name 
            FROM attendances a
            JOIN schedules sch ON a.schedule_id = sch.id
            JOIN subjects s ON sch.subject_id = s.id
            WHERE a.student_id = ? 
            ORDER BY a.date DESC LIMIT 50`, [id]);
        student.attendances = attendances;

        const [violations] = await db.execute('SELECT * FROM violations WHERE student_id = ? ORDER BY date DESC', [id]);
        student.violations = violations;

        const [health] = await db.execute('SELECT * FROM health_records WHERE student_id = ? ORDER BY date DESC, id DESC', [id]);
        student.health = health;

        const [permissions] = await db.execute('SELECT * FROM student_permissions WHERE student_id = ? ORDER BY start_date DESC', [id]);
        student.permissions = permissions;

        const [classHistory] = await db.execute(`
            SELECT ch.*, c.name as classroom_name, ay.name as academic_year_name, t.name as teacher_name
            FROM student_class_histories ch
            JOIN classrooms c ON ch.classroom_id = c.id
            JOIN academic_years ay ON ch.academic_year_id = ay.id
            LEFT JOIN teachers t ON c.homeroom_teacher_id = t.id
            WHERE ch.student_id = ?
            ORDER BY ay.name DESC`, [id]);
        student.class_history = classHistory;

        const [roomHistory] = await db.execute(`
            SELECT rh.*, dr.name as room_name, d.name as dormitory_name, d.mushrif_name
            FROM student_room_histories rh
            JOIN dormitory_rooms dr ON rh.dormitory_room_id = dr.id
            JOIN dormitories d ON dr.dormitory_id = d.id
            WHERE rh.student_id = ?
            ORDER BY rh.start_date DESC`, [id]);
        student.room_history = roomHistory;

        const [reports] = await db.execute(`
            SELECT ar.*, s.name as subject_name, ay.name as academic_year_name
            FROM academic_reports ar
            JOIN subjects s ON ar.subject_id = s.id
            JOIN academic_years ay ON ar.academic_year_id = ay.id
            WHERE ar.student_id = ?
            ORDER BY ay.name DESC, ar.semester DESC`, [id]);
        student.reports = reports;

        const [dailyGrades] = await db.execute(`
            SELECT sg.*, s.name as subject_name, ay.name as academic_year_name
            FROM student_grades sg
            JOIN subjects s ON sg.subject_id = s.id
            JOIN academic_years ay ON sg.academic_year_id = ay.id
            WHERE sg.student_id = ?
            ORDER BY sg.created_at DESC LIMIT 50`, [id]);
        student.daily_grades = dailyGrades;

        res.json(student);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  BILLING ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Get all unpaid bills for parent
app.get('/api/bills', protect, async (req, res) => {
    try {
        const userPhone = req.user.phone;
        const [bills] = await db.execute(`
            SELECT b.*, fc.name as category_name, s.name as student_name, s.id as student_id
            FROM bills b
            JOIN students s ON b.student_id = s.id
            LEFT JOIN fee_categories fc ON b.fee_category_id = fc.id
            WHERE s.parent_phone = ? AND b.status != 'paid'
            ORDER BY b.due_date ASC`, [userPhone]);
        res.json(bills);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// Get ALL bills (all statuses) - for history
app.get('/api/bills/all', protect, async (req, res) => {
    try {
        const userPhone = req.user.phone;
        const [bills] = await db.execute(`
            SELECT b.*, fc.name as category_name, s.name as student_name, s.id as student_id
            FROM bills b
            JOIN students s ON b.student_id = s.id
            LEFT JOIN fee_categories fc ON b.fee_category_id = fc.id
            WHERE s.parent_phone = ?
            ORDER BY b.due_date DESC`, [userPhone]);
        res.json(bills);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  WALLET ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Get Wallets and Balance
app.get('/api/wallets', protect, async (req, res) => {
    try {
        const userPhone = req.user.phone;
        const [wallets] = await db.execute(`
            SELECT w.*, s.name as student_name, s.nis 
            FROM wallets w
            JOIN students s ON w.student_id = s.id
            WHERE s.parent_phone = ?`, [userPhone]);
        res.json(wallets);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// Get Wallet Transactions
app.get('/api/wallets/:id/transactions', protect, async (req, res) => {
    try {
        const walletId = req.params.id;
        const userPhone = req.user.phone;

        const [check] = await db.execute(`
            SELECT w.id FROM wallets w
            JOIN students s ON w.student_id = s.id
            WHERE w.id = ? AND s.parent_phone = ?`, [walletId, userPhone]);

        if (check.length === 0) return res.status(403).json({ message: 'Akses ditolak.' });

        const [transactions] = await db.execute(`
            SELECT * FROM wallet_transactions 
            WHERE wallet_id = ? 
            ORDER BY created_at DESC, id DESC 
            LIMIT 50`, [walletId]);
        res.json(transactions);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// Transfer Balance between students (for parent)
app.post('/api/wallets/transfer', protect, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { from_wallet_id, to_wallet_id, amount } = req.body;
        const userPhone = req.user.phone;

        if (!from_wallet_id || !to_wallet_id || !amount || amount <= 0) {
            await connection.rollback();
            return res.status(400).json({ message: 'Data transfer tidak lengkap.' });
        }

        if (from_wallet_id === to_wallet_id) {
            await connection.rollback();
            return res.status(400).json({ message: 'Tidak bisa transfer ke dompet yang sama.' });
        }

        // Verify both wallets belong to the guardian's students
        const [wallets] = await connection.execute(`
            SELECT w.*, s.name as student_name FROM wallets w
            JOIN students s ON w.student_id = s.id
            WHERE w.id IN (?, ?) AND s.parent_phone = ?`,
            [from_wallet_id, to_wallet_id, userPhone]);

        if (wallets.length !== 2) {
            await connection.rollback();
            return res.status(403).json({ message: 'Akses ditolak atau dompet tidak ditemukan.' });
        }

        const fromWallet = wallets.find(w => w.id == from_wallet_id);
        const toWallet = wallets.find(w => w.id == to_wallet_id);

        if (Number(fromWallet.balance) < Number(amount)) {
            await connection.rollback();
            return res.status(400).json({ message: 'Saldo tidak mencukupi.' });
        }

        const fromBefore = Number(fromWallet.balance);
        const fromAfter = fromBefore - Number(amount);
        const toBefore = Number(toWallet.balance);
        const toAfter = toBefore + Number(amount);

        const refNo = 'TRF-' + Date.now();

        // Update Sender
        await connection.execute('UPDATE wallets SET balance = ? WHERE id = ?', [fromAfter, fromWallet.id]);
        await connection.execute(`
            INSERT INTO wallet_transactions (wallet_id, type, amount, balance_before, balance_after, reference, description)
            VALUES (?, 'withdrawal', ?, ?, ?, ?, ?)`,
            [fromWallet.id, amount, fromBefore, fromAfter, refNo, `Transfer ke ${toWallet.student_name}`]);

        // Update Receiver
        await connection.execute('UPDATE wallets SET balance = ? WHERE id = ?', [toAfter, toWallet.id]);
        await connection.execute(`
            INSERT INTO wallet_transactions (wallet_id, type, amount, balance_before, balance_after, reference, description)
            VALUES (?, 'deposit', ?, ?, ?, ?, ?)`,
            [toWallet.id, amount, toBefore, toAfter, refNo, `Terima dari ${fromWallet.student_name}`]);

        await connection.commit();

        // Notification for guardian
        await createNotification(req.user.id, 'transfer', 'Transfer Berhasil',
            `Transfer saldo Rp ${Number(amount).toLocaleString('id-ID')} dari ${fromWallet.student_name} ke ${toWallet.student_name} berhasil.`,
            { from_wallet_id, to_wallet_id });

        res.json({ message: 'Transfer berhasil.', new_balance: fromAfter });

    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal memproses transfer.' });
    } finally {
        connection.release();
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  XENDIT PAYMENT - TOPUP WALLET
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/topup/create', protect, async (req, res) => {
    try {
        const { wallet_id, amount } = req.body;
        const userPhone = req.user.phone;

        if (!wallet_id || !amount || amount < 10000) {
            return res.status(400).json({ message: 'Minimum topup Rp 10.000.' });
        }

        // Verify wallet ownership AND fetch pesantren info
        const [wallets] = await db.execute(`
            SELECT w.*, s.name as student_name, s.nis, p.id as pesantren_id, p.xendit_sub_account_id, p.platform_fee
            FROM wallets w
            JOIN students s ON w.student_id = s.id
            LEFT JOIN pesantrens p ON s.pesantren_id = p.id
            WHERE w.id = ? AND s.parent_phone = ?`, [wallet_id, userPhone]);

        if (wallets.length === 0) return res.status(403).json({ message: 'Dompet tidak ditemukan.' });

        const wallet = wallets[0];
        const externalId = `TOPUP-${wallet_id}-${uuidv4()}`;

        // Fetch user info for Xendit invoice
        const [users] = await db.execute('SELECT * FROM users WHERE phone = ?', [userPhone]);
        const user = users[0];

        let invoiceData;
        const subAccountId = wallet.xendit_sub_account_id;
        const platformFee = Number(wallet.platform_fee || 0);

        if (process.env.XENDIT_SECRET_KEY && process.env.XENDIT_SECRET_KEY !== '') {
            // Create Xendit Invoice with XenPlatform Split Payment logic
            const payload = {
                external_id: externalId,
                amount: Number(amount),
                payer_email: (user?.email && user.email.includes('@')) ? user.email : `${userPhone}@pesantren.id`,
                description: `Top Up E-Wallet - ${wallet.student_name} (${wallet.nis})`,
                success_redirect_url: `${process.env.XENDIT_SUCCESS_URL || FRONTEND_URL}?topup=success&ref=${externalId}`,
                failure_redirect_url: `${process.env.XENDIT_FAILURE_URL || FRONTEND_URL}?topup=failed`,
                invoice_duration: 3600,
                currency: 'IDR',
                items: [{
                    name: `Top Up E-Wallet ${wallet.student_name}`,
                    quantity: 1,
                    price: Number(amount)
                }]
            };

            // If it's a sub-account, add Platform Fee
            if (subAccountId) {
                if (platformFee > 0) {
                    payload.fees = [
                        {
                            type: 'PLATFORM_FEE',
                            value: platformFee
                        }
                    ];
                }
            }

            // Call Xendit with optionally for-user-id
            invoiceData = await xenditRequest('/v2/invoices', 'POST', payload, subAccountId);
        } else {
            // Demo mode
            invoiceData = {
                id: `demo_inv_${Date.now()}`,
                external_id: externalId,
                invoice_url: null,
                status: 'PENDING',
                amount: Number(amount)
            };
        }

        // Save pending topup record
        await db.execute(`
            INSERT INTO topup_logs (wallet_id, external_id, xendit_id, amount, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', NOW())`,
            [wallet_id, externalId, invoiceData.id, amount]);

        res.json({
            invoice_url: invoiceData.invoice_url,
            external_id: externalId,
            xendit_id: invoiceData.id,
            amount,
            student_name: wallet.student_name,
            pesantren_id: wallet.pesantren_id,
            platform_fee_applied: platformFee > 0 && !!subAccountId,
            demo_mode: !process.env.XENDIT_SECRET_KEY
        });
    } catch (err) {
        console.error('Topup create error:', err);
        const errMsg = err.data?.message || err.message || 'Gagal membuat invoice topup.';
        res.status(500).json({ message: `Xendit Error: ${errMsg}`, details: err.data });
    }
});

// Xendit Webhook - Invoice Paid
app.post('/api/xendit/webhook', async (req, res) => {
    try {
        // Verify webhook token
        const callbackToken = req.headers['x-callback-token'];
        const hookToken = process.env.XENDIT_WEBHOOK_TOKEN;
        if (hookToken && callbackToken !== hookToken) {
            return res.status(403).json({ message: 'Invalid webhook token.' });
        }

        const event = req.body;
        console.log('[XENDIT WEBHOOK]', JSON.stringify(event));

        if (event.status === 'PAID' || event.status === 'SETTLED') {
            const externalId = event.external_id;

            if (externalId.startsWith('DON-')) {
                // Process Donation
                const [donations] = await db.execute('SELECT * FROM donations WHERE reference_no = ? AND payment_status = ?', [externalId, 'pending']);
                if (donations.length > 0) {
                    const donation = donations[0];
                    const connection = await db.getConnection();
                    await connection.beginTransaction();
                    try {
                        await connection.execute('UPDATE donations SET payment_status = "success" WHERE id = ?', [donation.id]);
                        await connection.execute('UPDATE donation_campaigns SET collected_amount = collected_amount + ? WHERE id = ?', [donation.amount, donation.campaign_id]);
                        await connection.commit();

                        // Add Notification
                        if (donation.user_id) {
                            await createNotification(donation.user_id, 'donation', 'Donasi Berhasil', `Terima kasih! Donasi sebesar Rp ${Number(donation.amount).toLocaleString('id-ID')} untuk program donasi telah kami terima.`);
                        }

                        console.log('[WEBHOOK] Donation success:', externalId);
                        return res.json({ received: true });
                    } catch (err) {
                        await connection.rollback();
                        throw err;
                    } finally {
                        connection.release();
                    }
                }
            }

            // Split Payment SaaS Invoice Logic
            if (externalId.startsWith('INV-') || /^\\d+$/.test(externalId) || (event.fees && event.fees.length > 0)) {
                try {
                    const [txs] = await db.execute('SELECT id FROM transactions WHERE xendit_invoice_id = ? OR id = ?', [externalId, externalId]);
                    if (txs.length > 0) {
                        await db.execute(
                            `UPDATE transactions SET status = 'success', payment_channel = ?, updated_at = NOW() WHERE id = ?`,
                            [event.payment_channel || 'XENDIT', txs[0].id]
                        );
                        console.log('[WEBHOOK] Split Payment success for transaction id:', txs[0].id);
                        return res.json({ received: true });
                    }
                } catch (err) {
                    console.error('[WEBHOOK Split Payment Error]', err);
                }
            }

            // Bill Payment Logic
            if (externalId.startsWith('BILL-')) {
                const [logs] = await db.execute(
                    "SELECT * FROM topup_logs WHERE external_id = ? AND status = 'pending_bill'",
                    [externalId]
                );

                if (logs.length === 0) {
                    console.log('[WEBHOOK] Bill already processed or not found:', externalId);
                    return res.json({ received: true });
                }

                const log = logs[0];
                const meta = JSON.parse(log.notes || '{}');
                const bill_id = meta.bill_id;

                const connection = await db.getConnection();
                await connection.beginTransaction();

                try {
                    const [bills] = await connection.execute('SELECT * FROM bills WHERE id = ?', [bill_id]);
                    if (bills.length > 0) {
                        const bill = bills[0];
                        const newPaid = Number(bill.amount_paid) + Number(log.amount);
                        const status = newPaid >= Number(bill.amount) ? 'paid' : 'partial';

                        await connection.execute('UPDATE bills SET amount_paid = ?, status = ? WHERE id = ?', [newPaid, status, bill_id]);

                        const refNo = 'GW-' + Date.now();
                        await connection.execute(`
                            INSERT INTO transactions (reference_no, student_id, bill_id, fee_category_id, amount_paid, payment_date, payment_method, status)
                            VALUES (?, ?, ?, ?, ?, NOW(), 'gateway', 'success')`,
                            [refNo, bill.student_id, bill_id, bill.fee_category_id, log.amount]);

                        await connection.execute(
                            "UPDATE topup_logs SET status = 'success', paid_at = NOW() WHERE external_id = ?",
                            [externalId]);

                        // Find user to notify
                        const [users] = await connection.execute('SELECT u.id, s.name FROM users u JOIN students s ON s.parent_phone = u.phone WHERE s.id = ?', [bill.student_id]);
                        if (users.length > 0) {
                            await createNotification(users[0].id, 'payment', 'Pembayaran Tagihan Berhasil', `Pembayaran tagihan sebesar Rp ${Number(log.amount).toLocaleString('id-ID')} untuk ${users[0].name} via Xendit berhasil.`, { bill_id: bill_id });
                        }

                        await connection.commit();
                        console.log('[WEBHOOK] Bill payment success:', externalId);
                    } else {
                        await connection.rollback();
                    }
                } catch (err) {
                    await connection.rollback();
                    throw err;
                } finally {
                    connection.release();
                }
                return res.json({ received: true });
            }

            // Find the topup log (Existing logic for Topup)
            const [logs] = await db.execute(
                'SELECT * FROM topup_logs WHERE external_id = ? AND status = ?',
                [externalId, 'pending']
            );

            if (logs.length === 0) {
                console.log('[WEBHOOK] Topup already processed or not found:', externalId);
                return res.json({ received: true });
            }

            const log = logs[0];
            const connection = await db.getConnection();
            await connection.beginTransaction();

            try {
                // Get wallet
                const [wallets] = await connection.execute('SELECT * FROM wallets WHERE id = ?', [log.wallet_id]);
                const wallet = wallets[0];
                const before = Number(wallet.balance);
                const after = before + Number(log.amount);

                // Update wallet balance
                await connection.execute('UPDATE wallets SET balance = ? WHERE id = ?', [after, wallet.id]);

                // Create wallet transaction
                await connection.execute(`
                    INSERT INTO wallet_transactions (wallet_id, type, amount, balance_before, balance_after, reference, description)
                    VALUES (?, 'deposit', ?, ?, ?, ?, ?)`,
                    [wallet.id, log.amount, before, after, externalId, `Top Up via Xendit`]);

                await connection.execute(
                    "UPDATE topup_logs SET status = 'success', paid_at = NOW() WHERE external_id = ?",
                    [externalId]
                );

                // Add Notification
                const [users] = await connection.execute('SELECT u.id FROM users u JOIN students s ON s.parent_phone = u.phone JOIN wallets w ON w.student_id = s.id WHERE w.id = ?', [wallet.id]);
                if (users.length > 0) {
                    await createNotification(users[0].id, 'topup', 'Top Up Berhasil', `Pengisian saldo Rp ${Number(log.amount).toLocaleString('id-ID')} untuk ${wallet.student_name} telah berhasil.`, { wallet_id: wallet.id });
                }

                await connection.commit();
                console.log('[WEBHOOK] Topup success for wallet:', wallet.id, 'amount:', log.amount);
            } catch (err) {

                await connection.rollback();
                throw err;
            } finally {
                connection.release();
            }
        }

        res.json({ received: true });
    } catch (err) {
        console.error('[WEBHOOK ERROR]', err);
        res.status(500).json({ error: 'Webhook processing failed.' });
    }
});

// Check topup status
app.get('/api/topup/status/:external_id', protect, async (req, res) => {
    try {
        const { external_id } = req.params;
        const userPhone = req.user.phone;

        const [logs] = await db.execute(`
            SELECT tl.*, w.student_id FROM topup_logs tl
            JOIN wallets w ON tl.wallet_id = w.id
            JOIN students s ON w.student_id = s.id
            WHERE tl.external_id = ? AND s.parent_phone = ?`, [external_id, userPhone]);

        if (logs.length === 0) return res.status(404).json({ message: 'Transaksi tidak ditemukan.' });

        res.json(logs[0]);
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// Manual topup in demo mode (simulate payment complete)
app.post('/api/topup/demo-complete', protect, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { external_id } = req.body;
        const userPhone = req.user.phone;

        const [logs] = await connection.execute(`
            SELECT tl.*, w.id as wid FROM topup_logs tl
            JOIN wallets w ON tl.wallet_id = w.id
            JOIN students s ON w.student_id = s.id
            WHERE tl.external_id = ? AND s.parent_phone = ? AND tl.status = 'pending'`,
            [external_id, userPhone]);

        if (logs.length === 0) {
            await connection.rollback();
            return res.status(404).json({ message: 'Transaksi tidak ditemukan atau sudah diproses.' });
        }

        const log = logs[0];
        const [wallets] = await connection.execute('SELECT * FROM wallets WHERE id = ?', [log.wallet_id]);
        const wallet = wallets[0];
        const before = Number(wallet.balance);
        const after = before + Number(log.amount);

        await connection.execute('UPDATE wallets SET balance = ? WHERE id = ?', [after, wallet.id]);
        await connection.execute(`
            INSERT INTO wallet_transactions (wallet_id, type, amount, balance_before, balance_after, reference, description)
            VALUES (?, 'deposit', ?, ?, ?, ?, ?)`,
            [wallet.id, log.amount, before, after, log.external_id, 'Top Up (Simulasi)']);
        await connection.execute(
            "UPDATE topup_logs SET status = 'success', paid_at = NOW() WHERE external_id = ?",
            [log.external_id]);

        await connection.commit();

        // Notification for guardian
        await createNotification(req.user.id, 'topup', 'Top Up Berhasil (Simulasi)',
            `Pengisian saldo Rp ${Number(log.amount).toLocaleString('id-ID')} untuk ${wallet.student_name} telah berhasil disimulasikan.`,
            { wallet_id: wallet.id });

        res.json({ message: 'Top up berhasil disimulasikan.', new_balance: after });
    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal.' });
    } finally {
        connection.release();
    }
});

// Demo: simulate donation gateway payment
app.post('/api/donations/demo-complete', async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { reference_no } = req.body;
        const [donations] = await connection.execute('SELECT * FROM donations WHERE reference_no = ? AND payment_status = "pending"', [reference_no]);

        if (donations.length === 0) {
            await connection.rollback();
            return res.status(404).json({ message: 'Transaksi tidak ditemukan atau sudah diproses.' });
        }

        const donation = donations[0];
        await connection.execute('UPDATE donations SET payment_status = "success" WHERE id = ?', [donation.id]);
        await connection.execute('UPDATE donation_campaigns SET collected_amount = collected_amount + ? WHERE id = ?', [donation.amount, donation.campaign_id]);
        await connection.commit();

        // Notification for User
        if (donation.user_id) {
            await createNotification(donation.user_id, 'donation', 'Donasi Berhasil (Simulasi)', `Terima kasih! Infaq sebesar Rp ${Number(donation.amount).toLocaleString('id-ID')} telah berhasil disimulasikan.`);
        }

        res.json({ message: 'Donasi berhasil disimulasikan.' });
    } catch (err) {
        await connection.rollback();
        res.status(500).json({ error: 'Gagal.' });
    } finally {
        connection.release();
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  XENDIT PAYMENT - PAY BILL
// ═══════════════════════════════════════════════════════════════════════════════

// Create Xendit invoice for bill payment
app.post('/api/bills/pay-gateway', protect, async (req, res) => {
    try {
        const { bill_id, amount } = req.body;
        const userPhone = req.user.phone;

        if (!bill_id || !amount || amount <= 0) {
            return res.status(400).json({ message: 'Data tidak lengkap.' });
        }

        const [bills] = await db.execute(`
            SELECT b.*, s.id as student_id, s.name as student_name, w.id as wallet_id FROM bills b
            JOIN students s ON b.student_id = s.id
            JOIN wallets w ON s.id = w.student_id
            LEFT JOIN fee_categories fc ON b.fee_category_id = fc.id
            WHERE b.id = ? AND s.parent_phone = ?`, [bill_id, userPhone]);

        if (bills.length === 0) return res.status(404).json({ message: 'Tagihan tidak ditemukan.' });

        const bill = bills[0];
        const remaining = Number(bill.amount) - Number(bill.amount_paid);

        if (Number(amount) > remaining) return res.status(400).json({ message: 'Jumlah melebihi sisa tagihan.' });

        const externalId = `BILL-${bill_id}-${uuidv4()}`;
        const [users] = await db.execute('SELECT * FROM users WHERE phone = ?', [userPhone]);
        const user = users[0];

        let invoiceData;
        if (process.env.XENDIT_SECRET_KEY && process.env.XENDIT_SECRET_KEY !== '') {
            invoiceData = await xenditRequest('/v2/invoices', 'POST', {
                external_id: externalId,
                amount: Number(amount),
                payer_email: (user?.email && user.email.includes('@')) ? user.email : `${userPhone}@pesantren.id`,
                description: `Bayar Tagihan - ${bill.student_name} - ${bill.period_label || 'Reguler'}`,
                success_redirect_url: `${FRONTEND_URL}?bill_paid=success&ref=${externalId}`,
                failure_redirect_url: `${FRONTEND_URL}?bill_paid=failed`,
                invoice_duration: 3600,
                currency: 'IDR'
            });
        } else {
            invoiceData = {
                id: `demo_bill_${Date.now()}`,
                external_id: externalId,
                invoice_url: null,
                status: 'PENDING',
                amount: Number(amount)
            };
        }

        // Save pending bill payment record
        await db.execute(`
            INSERT INTO topup_logs (wallet_id, external_id, xendit_id, amount, status, created_at, notes)
            VALUES (?, ?, ?, ?, 'pending_bill', NOW(), ?)`,
            [bill.wallet_id, externalId, invoiceData.id, amount, JSON.stringify({ bill_id, student_id: bill.student_id })]);

        res.json({
            invoice_url: invoiceData.invoice_url,
            external_id: externalId,
            amount,
            demo_mode: !process.env.XENDIT_SECRET_KEY
        });
    } catch (err) {
        console.error('Bill pay gateway error:', err);
        const errMsg = err.data?.message || err.message || 'Gagal membuat invoice pembayaran.';
        res.status(500).json({ message: `Xendit Error: ${errMsg}`, details: err.data });
    }
});

// Pay bill via wallet
app.post('/api/bills/pay-wallet', protect, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { bill_id, amount } = req.body;
        const userPhone = req.user.phone;

        const [bills] = await connection.execute(`
            SELECT b.*, s.id as student_id FROM bills b
            JOIN students s ON b.student_id = s.id
            WHERE b.id = ? AND s.parent_phone = ?`, [bill_id, userPhone]);

        if (bills.length === 0) {
            await connection.rollback();
            return res.status(404).json({ message: 'Tagihan tidak ditemukan.' });
        }

        const bill = bills[0];
        const remaining = Number(bill.amount) - Number(bill.amount_paid);

        if (Number(amount) > remaining) {
            await connection.rollback();
            return res.status(400).json({ message: 'Jumlah bayar melebihi sisa tagihan.' });
        }

        // Get wallet
        const [wallets] = await connection.execute('SELECT * FROM wallets WHERE student_id = ?', [bill.student_id]);
        if (wallets.length === 0) {
            await connection.rollback();
            return res.status(404).json({ message: 'E-Wallet tidak ditemukan.' });
        }

        const wallet = wallets[0];
        if (Number(wallet.balance) < Number(amount)) {
            await connection.rollback();
            return res.status(400).json({ message: 'Saldo tidak mencukupi.' });
        }

        const before = Number(wallet.balance);
        const after = before - Number(amount);

        await connection.execute('UPDATE wallets SET balance = ? WHERE id = ?', [after, wallet.id]);

        const refNo = 'PAY-' + Date.now() + Math.floor(Math.random() * 1000);

        await connection.execute(`
            INSERT INTO wallet_transactions (wallet_id, type, amount, balance_before, balance_after, reference, description)
            VALUES (?, 'payment', ?, ?, ?, ?, ?)`,
            [wallet.id, amount, before, after, refNo, `Bayar: ${bill.period_label || 'Tagihan'}`]);

        const newPaid = Number(bill.amount_paid) + Number(amount);
        const status = newPaid >= Number(bill.amount) ? 'paid' : 'partial';
        await connection.execute('UPDATE bills SET amount_paid = ?, status = ? WHERE id = ?', [newPaid, status, bill.id]);

        await connection.execute(`
            INSERT INTO transactions (reference_no, student_id, bill_id, fee_category_id, amount_paid, payment_date, payment_method, status)
            VALUES (?, ?, ?, ?, ?, NOW(), 'wallet', 'success')`,
            [refNo, bill.student_id, bill.id, bill.fee_category_id, amount]);

        await connection.commit();

        await createNotification(req.user.id, 'payment', 'Pembayaran Berhasil', `Pembayaran tagihan sebesar Rp ${Number(amount).toLocaleString('id-ID')} via E-Wallet berhasil.`, { bill_id: bill.id });

        res.json({ message: 'Pembayaran berhasil dari E-Wallet.', reference: refNo, new_balance: after });

    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal memproses pembayaran.' });
    } finally {
        connection.release();
    }
});

// Demo: simulate bill gateway payment
app.post('/api/bills/demo-complete', protect, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { external_id } = req.body;
        const userPhone = req.user.phone;

        const [logs] = await connection.execute(
            "SELECT * FROM topup_logs WHERE external_id = ? AND status = 'pending_bill'",
            [external_id]);

        if (logs.length === 0) {
            await connection.rollback();
            return res.status(404).json({ message: 'Transaksi tidak ditemukan.' });
        }

        const log = logs[0];
        const meta = JSON.parse(log.notes || '{}');
        const bill_id = meta.bill_id;

        const [bills] = await connection.execute(`
            SELECT b.*, s.id as student_id FROM bills b
            JOIN students s ON b.student_id = s.id
            WHERE b.id = ? AND s.parent_phone = ?`, [bill_id, userPhone]);

        if (bills.length === 0) {
            await connection.rollback();
            return res.status(403).json({ message: 'Akses ditolak.' });
        }

        const bill = bills[0];
        const newPaid = Number(bill.amount_paid) + Number(log.amount);
        const status = newPaid >= Number(bill.amount) ? 'paid' : 'partial';

        await connection.execute('UPDATE bills SET amount_paid = ?, status = ? WHERE id = ?', [newPaid, status, bill_id]);

        const refNo = 'GW-' + Date.now();
        await connection.execute(`
            INSERT INTO transactions (reference_no, student_id, bill_id, fee_category_id, amount_paid, payment_date, payment_method, status)
            VALUES (?, ?, ?, ?, ?, NOW(), 'gateway', 'success')`,
            [refNo, bill.student_id, bill_id, bill.fee_category_id, log.amount]);

        await connection.execute(
            "UPDATE topup_logs SET status = 'success', paid_at = NOW() WHERE external_id = ?",
            [external_id]);

        await connection.commit();

        // Notification for guardian
        await createNotification(req.user.id, 'payment', 'Pembayaran Tagihan Berhasil (Simulasi)',
            `Pembayaran tagihan sebesar Rp ${Number(log.amount).toLocaleString('id-ID')} via Gateway (Simulasi) berhasil.`,
            { bill_id: bill_id });

        res.json({ message: 'Pembayaran tagihan berhasil.', reference: refNo });
    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal.' });
    } finally {
        connection.release();
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  PAYMENT HISTORY
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/payments/history', protect, async (req, res) => {
    try {
        const userPhone = req.user.phone;
        const [history] = await db.execute(`
            SELECT t.*, s.name as student_name, fc.name as category_name, b.period_label
            FROM transactions t
            JOIN students s ON t.student_id = s.id
            LEFT JOIN fee_categories fc ON t.fee_category_id = fc.id
            LEFT JOIN bills b ON t.bill_id = b.id
            WHERE s.parent_phone = ?
            ORDER BY t.payment_date DESC, t.id DESC
            LIMIT 50`, [userPhone]);
        res.json(history);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// All wallet transactions (topup + payment + canteen)
app.get('/api/payments/wallet-history', protect, async (req, res) => {
    try {
        const userPhone = req.user.phone;
        const [txns] = await db.execute(`
            SELECT wt.*, s.name as student_name, s.nis
            FROM wallet_transactions wt
            JOIN wallets w ON wt.wallet_id = w.id
            JOIN students s ON w.student_id = s.id
            WHERE s.parent_phone = ?
            ORDER BY wt.created_at DESC, wt.id DESC
            LIMIT 100`, [userPhone]);
        res.json(txns);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  RFID / FINGERPRINT CANTEEN (ADMIN ONLY)
// ═══════════════════════════════════════════════════════════════════════════════

// Lookup student by RFID or Fingerprint ID
app.post('/api/admin/student-lookup', protectAdmin, async (req, res) => {
    try {
        const { rfid, fingerprint_id } = req.body;
        if (!rfid && !fingerprint_id) return res.status(400).json({ message: 'RFID atau Fingerprint ID diperlukan.' });

        let query, param;
        if (rfid) {
            query = 'SELECT s.*, w.balance, w.id as wallet_id FROM students s LEFT JOIN wallets w ON s.id = w.student_id WHERE s.rfid = ?';
            param = rfid;
        } else {
            query = 'SELECT s.*, w.balance, w.id as wallet_id FROM students s LEFT JOIN wallets w ON s.id = w.student_id WHERE s.fingerprint_id = ?';
            param = fingerprint_id;
        }

        const [rows] = await db.execute(query, [param]);
        if (rows.length === 0) return res.status(404).json({ message: 'Santri tidak ditemukan.' });

        const student = rows[0];
        res.json({
            id: student.id,
            name: student.name,
            nis: student.nis,
            balance: student.balance || 0,
            wallet_id: student.wallet_id
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// Process canteen purchase via RFID/fingerprint
app.post('/api/admin/canteen-purchase', protectAdmin, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { wallet_id, amount, description, rfid, fingerprint_id } = req.body;

        if (!wallet_id || !amount || amount <= 0) {
            await connection.rollback();
            return res.status(400).json({ message: 'Data tidak lengkap.' });
        }

        const [wallets] = await connection.execute('SELECT * FROM wallets WHERE id = ?', [wallet_id]);
        if (wallets.length === 0) {
            await connection.rollback();
            return res.status(404).json({ message: 'Dompet tidak ditemukan.' });
        }

        const wallet = wallets[0];
        if (Number(wallet.balance) < Number(amount)) {
            await connection.rollback();
            return res.status(400).json({ message: 'Saldo tidak mencukupi.', balance: wallet.balance });
        }

        const before = Number(wallet.balance);
        const after = before - Number(amount);
        const refNo = 'CNTN-' + Date.now();

        await connection.execute('UPDATE wallets SET balance = ? WHERE id = ?', [after, wallet.id]);
        await connection.execute(`
            INSERT INTO wallet_transactions (wallet_id, type, amount, balance_before, balance_after, reference, description)
            VALUES (?, 'purchase', ?, ?, ?, ?, ?)`,
            [wallet.id, amount, before, after, refNo, description || 'Pembelian di Kantin']);

        await connection.commit();

        // Add Notification for Parent
        const [rows] = await connection.execute(`
            SELECT u.id as user_id, s.name as student_name 
            FROM users u 
            JOIN students s ON s.parent_phone = u.phone 
            WHERE s.id = ?`, [wallet.student_id]);

        if (rows.length > 0) {
            await createNotification(rows[0].user_id, 'canteen', 'Transaksi Kantin',
                `Ananda ${rows[0].student_name} baru saja jajan di kantin sebesar Rp ${Number(amount).toLocaleString('id-ID')}.`,
                { wallet_id: wallet.id });
        }

        res.json({ message: 'Transaksi kantin berhasil.', reference: refNo, new_balance: after });

    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal memproses transaksi kantin.' });
    } finally {
        connection.release();
    }
});

// Process withdrawal via RFID/fingerprint (tarik tunai)
app.post('/api/admin/withdraw', protectAdmin, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { wallet_id, amount } = req.body;

        if (!wallet_id || !amount || amount <= 0) {
            await connection.rollback();
            return res.status(400).json({ message: 'Data tidak lengkap.' });
        }

        const [wallets] = await connection.execute('SELECT * FROM wallets WHERE id = ?', [wallet_id]);
        const wallet = wallets[0];

        if (!wallet || Number(wallet.balance) < Number(amount)) {
            await connection.rollback();
            return res.status(400).json({ message: 'Saldo tidak mencukupi.', balance: wallet?.balance || 0 });
        }

        const before = Number(wallet.balance);
        const after = before - Number(amount);
        const refNo = 'WD-' + Date.now();

        await connection.execute('UPDATE wallets SET balance = ? WHERE id = ?', [after, wallet.id]);
        await connection.execute(`
            INSERT INTO wallet_transactions (wallet_id, type, amount, balance_before, balance_after, reference, description)
            VALUES (?, 'withdrawal', ?, ?, ?, ?, 'Tarik Tunai')`,
            [wallet.id, amount, before, after, refNo]);

        await connection.commit();

        // Add Notification
        const [rows2] = await connection.execute(`
            SELECT u.id as user_id, s.name as student_name 
            FROM users u 
            JOIN students s ON s.parent_phone = u.phone 
            WHERE s.id = ?`, [wallet.student_id]);

        if (rows2.length > 0) {
            await createNotification(rows2[0].user_id, 'withdrawal', 'Penarikan Tunai',
                `Penarikan tunai Rp ${Number(amount).toLocaleString('id-ID')} untuk Ananda ${rows2[0].student_name} telah diproses oleh admin.`,
                { wallet_id: wallet.id });
        }

        res.json({ message: 'Penarikan tunai berhasil.', reference: refNo, new_balance: after });

    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal.' });
    } finally {
        connection.release();
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/notifications', protect, async (req, res) => {
    try {
        const userId = req.user.id;
        const [notifs] = await db.execute(`
            SELECT *, is_read as 'read' FROM user_notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 50`, [userId]);

        res.json(notifs.map(n => ({
            ...n,
            read: !!n.read,
            time: n.created_at
        })));
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

app.post('/api/notifications/:id/read', protect, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        await db.execute('UPDATE user_notifications SET is_read = 1 WHERE id = ? AND user_id = ?', [id, userId]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.post('/api/notifications/read-all', protect, async (req, res) => {
    try {
        const userId = req.user.id;
        await db.execute('UPDATE user_notifications SET is_read = 1 WHERE user_id = ?', [userId]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});


// ═══════════════════════════════════════════════════════════════════════════════
//  ANNOUNCEMENTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/announcements', protect, async (req, res) => {
    try {
        const [posts] = await db.execute(`
            SELECT p.id, p.title, p.slug, p.excerpt, p.content, p.external_url, p.featured_image, p.published_at, p.type, u.name as author_name
            FROM posts p
            JOIN users u ON p.author_id = u.id
            WHERE p.is_published = 1 AND p.type = 'announcement'
            ORDER BY p.published_at DESC
            LIMIT 10
        `);
        res.json(posts);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

app.get('/api/articles', protect, async (req, res) => {
    try {
        const [posts] = await db.execute(`
            SELECT p.id, p.title, p.slug, p.excerpt, p.content, p.external_url, p.featured_image, p.published_at, p.type, u.name as author_name
            FROM posts p
            JOIN users u ON p.author_id = u.id
            WHERE p.is_published = 1 AND (p.type = 'news' OR p.type IS NULL)
            ORDER BY p.published_at DESC
            LIMIT 10
        `);
        res.json(posts);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});


// ═══════════════════════════════════════════════════════════════════════════════
//  PROFILE
// ═══════════════════════════════════════════════════════════════════════════════

app.put('/api/profile', protect, async (req, res) => {
    try {
        const { name, password } = req.body;
        const userId = req.user.id;

        if (!name) return res.status(400).json({ message: 'Nama tidak boleh kosong.' });

        let query = 'UPDATE users SET name = ?';
        let params = [name];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query += ', password = ?';
            params.push(hashedPassword);
        }

        query += ' WHERE id = ?';
        params.push(userId);
        await db.execute(query, params);

        res.json({ message: 'Profil berhasil diperbarui.', user: { name } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Gagal memperbarui profil.' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  RFID & PIN TERMINAL ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Verify RFID and Get Student info (Terminal Step 1)
app.post('/api/terminal/verify', async (req, res) => {
    try {
        const { rfid } = req.body;
        if (!rfid) return res.status(400).json({ message: 'RFID Required' });

        const [students] = await db.execute(`
            SELECT s.id, s.name, s.nis, w.balance, w.id as wallet_id, CASE WHEN w.pin IS NOT NULL THEN 1 ELSE 0 END as has_pin
            FROM students s
            JOIN wallets w ON s.id = w.student_id
            WHERE s.rfid = ?`, [rfid]);

        if (students.length === 0) return res.status(404).json({ message: 'ID Kartu tidak dikenali.' });

        const student = students[0];
        res.json({ student });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// Process Transaction (Terminal Step 2: RFID + PIN)
app.post('/api/terminal/transaction', async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { rfid, pin, amount, type, description } = req.body; // type: 'purchase', 'withdrawal', 'deposit'

        if (!rfid || !amount || !type) {
            await connection.rollback();
            return res.status(400).json({ message: 'Input tidak lengkap.' });
        }

        const [students] = await connection.execute(`
            SELECT s.id, s.name, s.parent_phone, w.id as wallet_id, w.balance, w.pin
            FROM students s
            JOIN wallets w ON s.id = w.student_id
            WHERE s.rfid = ?`, [rfid]);

        if (students.length === 0) {
            await connection.rollback();
            return res.status(404).json({ message: 'Kartu tidak terdaftar.' });
        }

        const student = students[0];

        // 1. Verify PIN (Mandatory for anything other than special cases)
        if (student.pin && student.pin !== pin) {
            await connection.rollback();
            return res.status(401).json({ message: 'PIN Salah.' });
        }

        if (!student.pin) {
            await connection.rollback();
            return res.status(400).json({ message: 'PIN belum diatur oleh Wali Santri. Atur PIN di menu Profil.' });
        }

        const before = Number(student.balance);
        let after = before;
        const refPrefix = type === 'purchase' ? 'CNTN' : (type === 'withdrawal' ? 'WD' : 'DEP');
        const refNo = `${refPrefix}-${Date.now()}`;

        if (type === 'deposit') {
            after += Number(amount);
        } else {
            if (before < Number(amount)) {
                await connection.rollback();
                return res.status(400).json({ message: 'Saldo tidak mencukupi.' });
            }
            after -= Number(amount);
        }

        // 2. Update Balance
        await connection.execute('UPDATE wallets SET balance = ? WHERE id = ?', [after, student.wallet_id]);

        // 3. Log Transaction
        await connection.execute(`
            INSERT INTO wallet_transactions (wallet_id, type, amount, balance_before, balance_after, reference, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [student.wallet_id, type, amount, before, after, refNo, description || 'Transaksi Terminal']);

        await connection.commit();

        // 4. Notify Parent
        const [users] = await db.execute('SELECT id FROM users WHERE phone = ?', [student.parent_phone]);
        if (users.length > 0) {
            const label = type === 'purchase' ? 'Pembelian Kantin' : (type === 'withdrawal' ? 'Tarik Tunai' : 'Setor Tunai');
            const verb = type === 'deposit' ? 'berhasil menyetor' : 'baru saja menarik/menggunakan';
            await createNotification(users[0].id, type, label,
                `Ananda ${student.name} ${verb} dana sebesar Rp ${Number(amount).toLocaleString('id-ID')} via Kartu RFID.`,
                { wallet_id: student.wallet_id, type });
        }

        res.json({ message: 'Transaksi Berhasil', reference: refNo, new_balance: after });

    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal memproses transaksi terminal.' });
    } finally {
        connection.release();
    }
});

// Update Wallet PIN (from Wali Santri App)
app.post('/api/wallets/:id/pin', protect, async (req, res) => {
    try {
        const { pin } = req.body;
        const walletId = req.params.id;
        const userPhone = req.user.phone;

        if (!/^\d{6}$/.test(pin)) return res.status(400).json({ message: 'PIN harus 6 digit angka.' });

        // Verify ownership
        const [check] = await db.execute(`
            SELECT w.id FROM wallets w
            JOIN students s ON w.student_id = s.id
            WHERE w.id = ? AND s.parent_phone = ?`, [walletId, userPhone]);

        if (check.length === 0) return res.status(403).json({ message: 'Akses ditolak.' });

        await db.execute('UPDATE wallets SET pin = ? WHERE id = ?', [pin, walletId]);
        res.json({ message: 'PIN Kartu/Wallet berhasil diperbarui.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  DONATION ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Get all active campaigns
app.get('/api/donations/campaigns', async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM donation_campaigns WHERE status = "active" ORDER BY created_at DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// Get campaign details with stats
app.get('/api/donations/campaigns/:id', async (req, res) => {
    try {
        const [campaigns] = await db.execute('SELECT * FROM donation_campaigns WHERE id = ?', [req.params.id]);
        if (campaigns.length === 0) return res.status(404).json({ message: 'Kampanye tidak ditemukan.' });

        const [donations] = await db.execute(`
            SELECT d.*, u.name as user_name 
            FROM donations d 
            LEFT JOIN users u ON d.user_id = u.id 
            WHERE d.campaign_id = ? AND d.payment_status = "success" 
            ORDER BY d.created_at DESC, d.id DESC LIMIT 10`, [req.params.id]);

        const [distributions] = await db.execute('SELECT * FROM donation_distributions WHERE campaign_id = ? ORDER BY distribution_date DESC', [req.params.id]);

        res.json({ campaign: campaigns[0], recent_donations: donations, distributions });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// Create Donation (Public/User)
app.post('/api/donations', async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const campaign_id = req.body.campaign_id;
        const student_id = req.body.student_id || null;
        const amount = Number(req.body.amount);
        const payment_method = req.body.payment_method;
        const notes = req.body.notes || null;

        console.log(`[DONATION] Attempting donation: ${amount} to campaign ${campaign_id} via ${payment_method}`);

        // Auth is optional for donations but if token present, use it
        let userId = null;
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer')) {
            try {
                const token = authHeader.split(' ')[1];
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                userId = decoded.id;
            } catch (e) {
                console.log('[DONATION] Invalid token, proceeding as guest');
            }
        }

        if (!campaign_id || !amount || amount < 1000) {
            return res.status(400).json({ message: 'Data tidak lengkap. Minimal donasi Rp 1.000.' });
        }

        const refNo = 'DON-' + Date.now() + Math.floor(Math.random() * 1000);

        if (payment_method === 'wallet') {
            if (!userId) return res.status(401).json({ message: 'Silakan login untuk donasi via E-Wallet.' });
            if (!student_id) return res.status(400).json({ message: 'Pilih santri untuk donasi via E-Wallet.' });

            // Deduct from wallet
            const [wallets] = await connection.execute('SELECT * FROM wallets WHERE student_id = ?', [student_id]);
            if (wallets.length === 0) {
                await connection.rollback();
                return res.status(404).json({ message: 'E-Wallet santri tidak ditemukan.' });
            }
            const wallet = wallets[0];

            if (Number(wallet.balance) < Number(amount)) {
                await connection.rollback();
                return res.status(400).json({ message: 'Saldo E-Wallet tidak mencukupi.' });
            }

            const before = Number(wallet.balance);
            const after = before - Number(amount);

            await connection.execute('UPDATE wallets SET balance = ? WHERE id = ?', [after, wallet.id]);
            await connection.execute(`
                INSERT INTO wallet_transactions (wallet_id, type, amount, balance_before, balance_after, reference, description)
                VALUES (?, 'withdrawal', ?, ?, ?, ?, ?)`,
                [wallet.id, amount, before, after, refNo, `Donasi: ${refNo}`]);

            // Create success donation record
            await connection.execute(`
                INSERT INTO donations (campaign_id, user_id, student_id, amount, payment_method, payment_status, reference_no, notes)
                VALUES (?, ?, ?, ?, ?, 'success', ?, ?)`,
                [campaign_id, userId, student_id, amount, 'wallet', refNo, notes]);

            // Update campaign collected amount
            await connection.execute('UPDATE donation_campaigns SET collected_amount = collected_amount + ? WHERE id = ?', [amount, campaign_id]);
            await connection.commit();

            // Add Notification
            await createNotification(userId, 'donation', 'Donasi E-Wallet Berhasil', `Terima kasih! Infaq sebesar Rp ${Number(amount).toLocaleString('id-ID')} via E-Wallet santri telah kami terima.`);

            console.log(`[DONATION] Success via wallet: ${refNo}`);
            return res.json({ message: 'Donasi berhasil menggunakan E-Wallet.', reference_no: refNo });

        } else if (payment_method === 'gateway') {
            const [campaigns] = await connection.execute('SELECT title FROM donation_campaigns WHERE id = ?', [campaign_id]);
            const campaignName = campaigns[0]?.title || 'Donasi';

            let invoiceUrl = null;
            let externalId = refNo;

            if (process.env.XENDIT_SECRET_KEY && process.env.XENDIT_SECRET_KEY !== '') {
                try {
                    const invoice = await xenditRequest('/v2/invoices', 'POST', {
                        external_id: externalId,
                        amount: Number(amount),
                        description: `Donasi Pesantren: ${campaignName}`,
                        success_redirect_url: `${FRONTEND_URL}/donasi?status=success&ref=${externalId}`,
                        failure_redirect_url: `${FRONTEND_URL}/donasi?status=failed`,
                        currency: 'IDR'
                    });
                    invoiceUrl = invoice.invoice_url;
                } catch (xerr) {
                    console.error('[XENDIT ERROR]', xerr);
                    // Fallback if Xendit request fails
                }
            }

            // Create pending donation record
            await connection.execute(`
                INSERT INTO donations (campaign_id, user_id, student_id, amount, payment_method, payment_status, reference_no, notes)
                VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`,
                [campaign_id, userId, student_id, amount, 'gateway', externalId, notes]);

            await connection.commit();
            console.log(`[DONATION] Success creating gateway invoice: ${externalId}`);
            return res.json({
                successRedirectUrl: process.env.XENDIT_SUCCESS_URL || 'http://localhost:3000/wallet',
                failureRedirectUrl: process.env.XENDIT_FAILURE_URL || 'http://localhost:3000/wallet',
                reference_no: externalId,
                demo_mode: !process.env.XENDIT_SECRET_KEY
            });
        }

        await connection.rollback();
        res.status(400).json({ message: 'Metode pembayaran tidak valid.' });

    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal memproses donasi.' });
    } finally {
        connection.release();
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  TEACHER ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Teacher Schedule
app.get('/api/teacher/schedule', protect, async (req, res) => {
    try {
        const userId = req.user.id;
        const [rows] = await db.execute(`
            SELECT sch.*, c.name as classroom_name, s.name as subject_name
            FROM schedules sch
            JOIN classrooms c ON sch.classroom_id = c.id
            JOIN subjects s ON sch.subject_id = s.id
            WHERE sch.teacher_id = ?
            ORDER BY FIELD(sch.day, 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu', 'Minggu'), sch.start_time ASC`, [userId]);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// Classroom Students
app.get('/api/teacher/classroom/:id/students', protect, async (req, res) => {
    try {
        const classroomId = req.params.id;
        const [rows] = await db.execute(`
            SELECT s.id, s.nis, s.name, s.gender, s.photo
            FROM students s
            WHERE s.classroom_id = ? AND s.status = 'active'
            ORDER BY s.name ASC`, [classroomId]);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// Submit Attendance
app.post('/api/teacher/attendance', protect, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { schedule_id, date, students } = req.body;
        if (!schedule_id || !date || !students) {
            await connection.rollback();
            return res.status(400).json({ message: 'Data tidak lengkap.' });
        }

        for (const s of students) {
            // Optional: Verify student is still active before recording attendance
            const [checkActive] = await connection.execute('SELECT status FROM students WHERE id = ?', [s.id]);
            if (checkActive.length > 0 && checkActive[0].status === 'active') {
                await connection.execute(`
                    INSERT INTO attendances (student_id, schedule_id, date, status, notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, NOW(), NOW())
                    ON DUPLICATE KEY UPDATE status = VALUES(status), notes = VALUES(notes), updated_at = NOW()`,
                    [s.id, schedule_id, date, s.status, s.notes || '']);
            }
        }

        await connection.commit();
        res.json({ message: 'Absensi berhasil disimpan.' });
    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    } finally {
        connection.release();
    }
});

// Submit Journal
app.post('/api/teacher/journal', protect, async (req, res) => {
    try {
        const { schedule_id, date, topic, note } = req.body;
        if (!schedule_id || !date || !topic) return res.status(400).json({ message: 'Topic wajib diisi.' });

        await db.execute(`
            INSERT INTO journals (schedule_id, date, topic, note, created_at, updated_at)
            VALUES (?, ?, ?, ?, NOW(), NOW())`,
            [schedule_id, date, topic, note || '']);
        res.json({ message: 'Jurnal pengajaran berhasil disimpan.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// Tahfidz Monitoring - Get All Students (Filtered by Teacher)
app.get('/api/teacher/students', protect, async (req, res) => {
    try {
        const userId = req.user.id;
        const [teachers] = await db.execute('SELECT id FROM teachers WHERE user_id = ?', [userId]);

        if (teachers.length === 0) {
            return res.status(403).json({ message: 'Akses ditolak. Profil guru tidak ditemukan.' });
        }

        const teacherId = teachers[0].id;

        const [rows] = await db.execute(`
            SELECT s.id, s.nis, s.name, s.photo, c.name as classroom_name
            FROM students s
            LEFT JOIN classrooms c ON s.classroom_id = c.id
            WHERE s.tahfidz_teacher_id = ? AND s.status = 'active'
            ORDER BY s.name ASC`, [teacherId]);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// Tahfidz Monitoring - Post Record
app.post('/api/teacher/tahfidz', protect, async (req, res) => {
    try {
        const userId = req.user.id;
        const [teachers] = await db.execute('SELECT id FROM teachers WHERE user_id = ?', [userId]);

        if (teachers.length === 0) {
            return res.status(403).json({ message: 'Akses ditolak. Profil guru tidak ditemukan.' });
        }

        const teacherId = teachers[0].id;
        const { student_id, type, content, status, note, date } = req.body;

        if (!student_id || !type || !content || !status) {
            return res.status(400).json({ message: 'Data setoran tidak lengkap.' });
        }

        // Verify student is active
        const [checkActiveT] = await db.execute('SELECT status FROM students WHERE id = ?', [student_id]);
        if (checkActiveT.length === 0 || checkActiveT[0].status !== 'active') {
            return res.status(400).json({ message: 'Hanya santri aktif yang dapat melakukan setoran hafalan.' });
        }

        await db.execute(`
            INSERT INTO tahfidz_records (student_id, teacher_id, type, content, date, status, note, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
            [student_id, teacherId, type, content, date || new Date().toISOString().split('T')[0], status, note || '']);

        res.json({ message: 'Catatan hafalan berhasil disimpan.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ─── Wali Kelas Features ───

// Get Classroom managed by Teacher (Wali Kelas)
app.get('/api/teacher/my-classroom', protect, async (req, res) => {
    try {
        const userId = req.user.id;
        const [rows] = await db.execute(`
            SELECT c.* 
            FROM classrooms c
            WHERE c.homeroom_teacher_id = ?`, [userId]);

        if (rows.length === 0) return res.json(null);

        const classroom = rows[0];

        // Fetch students in this class
        const [students] = await db.execute(`
            SELECT id, nis, name, gender, photo
            FROM students
            WHERE classroom_id = ? AND status = 'active'
            ORDER BY name ASC`, [classroom.id]);

        classroom.students = students;

        // Fetch full schedule for this classroom
        const [schedule] = await db.execute(`
            SELECT sch.*, s.name as subject_name, u.name as teacher_name
            FROM schedules sch
            JOIN subjects s ON sch.subject_id = s.id
            JOIN users u ON sch.teacher_id = u.id
            WHERE sch.classroom_id = ?
            ORDER BY FIELD(sch.day, 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu', 'Minggu'), sch.start_time ASC`, [classroom.id]);

        classroom.schedule = schedule;
        res.json(classroom);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// Classroom Academic & Attendance Monitoring (Wali Kelas)
app.get('/api/teacher/classroom/:id/monitoring', protect, async (req, res) => {
    try {
        const classroomId = req.params.id;
        const userId = req.user.id;

        // Verify Wali Kelas
        const [check] = await db.execute('SELECT id FROM classrooms WHERE id = ? AND homeroom_teacher_id = ?', [classroomId, userId]);
        if (check.length === 0) return res.status(403).json({ message: 'Akses ditolak. Anda bukan Wali Kelas di kelas ini.' });

        // Get Attendance Summary (last 30 days)
        const [attendanceSummary] = await db.execute(`
            SELECT s.name, 
                COUNT(CASE WHEN a.status = 'Hadir' THEN 1 END) as hadir,
                COUNT(CASE WHEN a.status = 'Izin' THEN 1 END) as izin,
                COUNT(CASE WHEN a.status = 'Sakit' THEN 1 END) as sakit,
                COUNT(CASE WHEN a.status = 'Alpa' THEN 1 END) as alpa
            FROM students s
            LEFT JOIN attendances a ON s.id = a.student_id AND a.date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            WHERE s.classroom_id = ? AND s.status = 'active'
            GROUP BY s.id, s.name
            ORDER BY s.name ASC`, [classroomId]);

        // Get Academic Summary (Recent Grades)
        const [gradeSummary] = await db.execute(`
            SELECT s.name, sub.name as subject_name, sg.type, sg.score, ay.term_label, sg.semester
            FROM students s
            JOIN student_grades sg ON s.id = sg.student_id
            JOIN subjects sub ON sg.subject_id = sub.id
            JOIN academic_years ay ON sg.academic_year_id = ay.id
            WHERE s.classroom_id = ? AND s.status = 'active'
            ORDER BY sg.created_at DESC LIMIT 50`, [classroomId]);

        res.json({ attendanceSummary, gradeSummary });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ─── Grade Management ───

app.get('/api/teacher/academic-years', protect, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT id, name, is_active, term_label, total_terms, active_term FROM academic_years ORDER BY name DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.post('/api/teacher/grades', protect, async (req, res) => {
    try {
        const userId = req.user.id;
        const { student_id, subject_id, academic_year_id, semester, type, score, note } = req.body;

        if (!student_id || !subject_id || !academic_year_id || !semester || !type || score === undefined) {
            return res.status(400).json({ message: 'Data nilai tidak lengkap.' });
        }

        // Verify student is active
        const [checkActive] = await db.execute('SELECT status FROM students WHERE id = ?', [student_id]);
        if (checkActive.length === 0 || checkActive[0].status !== 'active') {
            return res.status(400).json({ message: 'Hanya santri aktif yang dapat menerima nilai akademik.' });
        }

        await db.execute(`
            INSERT INTO student_grades (student_id, subject_id, teacher_id, academic_year_id, semester, type, score, note, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
            [student_id, subject_id, userId, academic_year_id, semester, type, score, note || '']);

        res.json({ message: 'Nilai berhasil disimpan.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ─── Teacher Activity ───

app.get('/api/teacher/activity', protect, async (req, res) => {
    try {
        const userId = req.user.id;

        // Activity from student attendance
        const [attendanceLogs] = await db.execute(`
            SELECT DISTINCT a.date, 'Absensi Siswa' as activity, c.name as classroom_name, s.name as subject_name
            FROM attendances a
            JOIN schedules sch ON a.schedule_id = sch.id
            JOIN classrooms c ON sch.classroom_id = c.id
            JOIN subjects s ON sch.subject_id = s.id
            WHERE sch.teacher_id = ?
            ORDER BY a.date DESC LIMIT 20`, [userId]);

        // Activity from journals
        const [journalLogs] = await db.execute(`
            SELECT j.date, 'Isi Jurnal' as activity, c.name as classroom_name, s.name as subject_name
            FROM journals j
            JOIN schedules sch ON j.schedule_id = sch.id
            JOIN classrooms c ON sch.classroom_id = c.id
            JOIN subjects s ON sch.subject_id = s.id
            WHERE sch.teacher_id = ?
            ORDER BY j.date DESC LIMIT 20`, [userId]);

        const combined = [...attendanceLogs, ...journalLogs].sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 30);
        res.json(combined);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ─── Dashboard Stats ───
app.get('/api/teacher/dashboard-stats', protect, async (req, res) => {
    try {
        const userId = req.user.id;

        // And number of students this teacher teaches (distinct students in their schedules)
        // Check `schedules` -> `classrooms` -> `students`
        const [studentsCountResult] = await db.execute(`
            SELECT COUNT(DISTINCT s.id) as studentsCount
            FROM students s
            JOIN classrooms c ON s.classroom_id = c.id
            JOIN schedules sch ON sch.classroom_id = c.id
            WHERE sch.teacher_id = ? AND s.status = 'active'
        `, [userId]);

        // Get count of inputs to student_grades today by this teacher
        const [gradesToday] = await db.execute(`
            SELECT COUNT(*) as gradesCount 
            FROM student_grades 
            WHERE teacher_id = ? AND DATE(created_at) = CURDATE()
        `, [userId]);

        res.json({
            gradesCount: gradesToday[0].gradesCount || 0,
            studentsCount: studentsCountResult[0].studentsCount || 0
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════════════════════════════════════════════


// ─── Classroom Exams (Admin-published, read-only for teacher) ───

app.get('/api/teacher/classroom/:id/exams', protect, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT ce.*, ay.name as academic_year_name, ay.term_label, ay.total_terms
            FROM classroom_exams ce
            LEFT JOIN academic_years ay ON ce.academic_year_id = ay.id
            WHERE ce.classroom_id = ? AND ce.status = 'published'
            ORDER BY ce.exam_date DESC`, [req.params.id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.post('/api/teacher/classroom/:id/exams', protect, async (req, res) => {
    try {
        const { name, exam_date, description, subject_id } = req.body;
        const formattedDate = exam_date === '' ? null : exam_date;

        // Find active academic year
        const [ays] = await db.execute('SELECT id, active_term FROM academic_years WHERE is_active = 1 LIMIT 1');
        const activeAY = ays[0];

        const [result] = await db.execute(
            'INSERT INTO classroom_exams (classroom_id, academic_year_id, term, subject_id, name, exam_date, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, "draft", NOW(), NOW())',
            [req.params.id, activeAY?.id || null, activeAY?.active_term || 1, subject_id || null, name, formattedDate, description || '']
        );
        res.json({ id: result.insertId, message: 'Ujian berhasil dibuat.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

app.delete('/api/teacher/exams/:examId', protect, async (req, res) => {
    try {
        await db.execute('DELETE FROM classroom_exams WHERE id = ?', [req.params.examId]);
        res.json({ message: 'Ujian berhasil dihapus.' });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// ─── Student Grades API ───────────────────────────────────────────────────────

// GET grades for a classroom/exam
app.get('/api/teacher/grades', protect, async (req, res) => {
    try {
        const { classroom_id, academic_year_id, term, type, classroom_exam_id } = req.query;
        let sql = `
            SELECT sg.*, s.name as student_name, s.nis, sub.name as subject_name, u.name as teacher_name
            FROM student_grades sg
            JOIN students s ON sg.student_id = s.id
            JOIN subjects sub ON sg.subject_id = sub.id
            LEFT JOIN users u ON sg.teacher_id = u.id
            WHERE 1=1`;
        const params = [];

        if (classroom_id) { sql += ' AND sg.classroom_id = ?'; params.push(classroom_id); }
        if (academic_year_id) { sql += ' AND sg.academic_year_id = ?'; params.push(academic_year_id); }
        if (term) { sql += ' AND sg.term = ?'; params.push(term); }
        if (type) { sql += ' AND sg.type = ?'; params.push(type); }
        if (classroom_exam_id) { sql += ' AND sg.classroom_exam_id = ?'; params.push(classroom_exam_id); }

        sql += ' ORDER BY s.name ASC';
        const [rows] = await db.execute(sql, params);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// POST - input/upsert grade for one student
app.post('/api/teacher/grades', protect, async (req, res) => {
    try {
        const userId = req.user.id;
        const { student_id, subject_id, academic_year_id, semester, term, type, score, note, classroom_exam_id, classroom_id } = req.body;

        if (!student_id || !subject_id || !academic_year_id || score === undefined) {
            return res.status(400).json({ message: 'Data tidak lengkap.' });
        }

        // Upsert logic - check if exists
        const [existing] = await db.execute(`
            SELECT id FROM student_grades
            WHERE student_id = ? AND subject_id = ? AND academic_year_id = ? AND term = ? AND type = ?
            ${classroom_exam_id ? 'AND classroom_exam_id = ?' : 'AND classroom_exam_id IS NULL'}`,
            classroom_exam_id
                ? [student_id, subject_id, academic_year_id, term || semester || 1, type, classroom_exam_id]
                : [student_id, subject_id, academic_year_id, term || semester || 1, type]
        );

        if (existing.length > 0) {
            await db.execute(
                'UPDATE student_grades SET score = ?, note = ?, teacher_id = ?, updated_at = NOW() WHERE id = ?',
                [score, note || null, userId, existing[0].id]
            );
            return res.json({ message: 'Nilai berhasil diperbarui.', id: existing[0].id, updated: true });
        }

        const [result] = await db.execute(`
            INSERT INTO student_grades 
                (student_id, subject_id, teacher_id, academic_year_id, semester, term, type, score, note, classroom_exam_id, classroom_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
            [student_id, subject_id, userId, academic_year_id,
                semester || term || 1, term || semester || 1,
                type, score, note || null,
                classroom_exam_id || null, classroom_id || null]
        );
        res.json({ message: 'Nilai berhasil disimpan.', id: result.insertId, updated: false });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// POST - bulk save grades for entire class
app.post('/api/teacher/grades/bulk', protect, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const userId = req.user.id;
        const { grades } = req.body; // array of grade objects

        if (!Array.isArray(grades) || grades.length === 0) {
            await connection.rollback();
            return res.status(400).json({ message: 'Data nilai tidak valid.' });
        }

        let saved = 0;
        let updated = 0;

        for (const g of grades) {
            const { student_id, subject_id, academic_year_id, semester, term, type, score, note, classroom_exam_id, classroom_id } = g;

            const [existing] = await connection.execute(`
                SELECT id FROM student_grades
                WHERE student_id = ? AND subject_id = ? AND academic_year_id = ? AND term = ? AND type = ?
                ${classroom_exam_id ? 'AND classroom_exam_id = ?' : 'AND classroom_exam_id IS NULL'}`,
                classroom_exam_id
                    ? [student_id, subject_id, academic_year_id, term || semester || 1, type, classroom_exam_id]
                    : [student_id, subject_id, academic_year_id, term || semester || 1, type]
            );

            if (existing.length > 0) {
                await connection.execute(
                    'UPDATE student_grades SET score = ?, note = ?, teacher_id = ?, updated_at = NOW() WHERE id = ?',
                    [score, note || null, userId, existing[0].id]
                );
                updated++;
            } else {
                await connection.execute(`
                    INSERT INTO student_grades 
                        (student_id, subject_id, teacher_id, academic_year_id, semester, term, type, score, note, classroom_exam_id, classroom_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                    [student_id, subject_id, userId, academic_year_id,
                        semester || term || 1, term || semester || 1,
                        type, score, note || null,
                        classroom_exam_id || null, classroom_id || null]
                );
                saved++;
            }
        }

        await connection.commit();
        res.json({ message: `${saved} nilai disimpan, ${updated} nilai diperbarui.`, saved, updated });
    } catch (err) {
        await connection.rollback();
        console.error('BULK GRADE ERROR:', err);
        res.status(500).json({ error: 'Gagal menyimpan nilai: ' + (err.sqlMessage || err.message) });
    } finally {
        connection.release();
    }
});

// ─── Report Card (Raport) — Wali Kelas ───────────────────────────────────────

// GET report card summary for all students in classroom
app.get('/api/teacher/classroom/:id/report-summary', protect, async (req, res) => {
    try {
        const classroomId = req.params.id;
        const { academic_year_id, term } = req.query;

        // Get all students in classroom
        const [students] = await db.execute(
            'SELECT id, name, nis, gender, photo FROM students WHERE classroom_id = ? AND status = "active" ORDER BY name',
            [classroomId]
        );

        if (students.length === 0) return res.json({ students: [], grades: [] });

        // Get all grades for this classroom/year/term
        let gradesSql = `
            SELECT sg.student_id, sg.subject_id, sub.name as subject_name,
                   sg.type, sg.term, sg.score, sg.note
            FROM student_grades sg
            JOIN subjects sub ON sg.subject_id = sub.id
            WHERE sg.classroom_id = ?`;
        const params = [classroomId];

        if (academic_year_id) { gradesSql += ' AND sg.academic_year_id = ?'; params.push(academic_year_id); }
        if (term) { gradesSql += ' AND sg.term = ?'; params.push(term); }

        const [grades] = await db.execute(gradesSql, params);

        // Get attendance summary per student (last 30 days of this academic year)
        const [attendance] = await db.execute(`
            SELECT a.student_id,
                   SUM(a.status = 'hadir') as hadir,
                   SUM(a.status = 'izin')  as izin,
                   SUM(a.status = 'sakit') as sakit,
                   SUM(a.status = 'alpa')  as alpa
            FROM attendances a
            JOIN schedules sch ON a.schedule_id = sch.id
            WHERE sch.classroom_id = ?
            GROUP BY a.student_id`, [classroomId]);

        // Get existing academic_reports (published raport)
        const [existingReports] = await db.execute(`
            SELECT ar.student_id, ar.id as report_id, ar.semester, ar.note as raport_note
            FROM academic_reports ar
            JOIN students s ON ar.student_id = s.id
            WHERE s.classroom_id = ?
            ${academic_year_id ? 'AND ar.academic_year_id = ?' : ''}
            ${term ? 'AND ar.semester = ?' : ''}`,
            [classroomId, ...(academic_year_id ? [academic_year_id] : []), ...(term ? [term] : [])]
        );

        // Map attendance
        const attendanceMap = {};
        attendance.forEach(a => { attendanceMap[a.student_id] = a; });

        // Map reports
        const reportMap = {};
        existingReports.forEach(r => { reportMap[r.student_id] = r; });

        res.json({ students, grades, attendanceMap, reportMap });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// GET individual student report card
app.get('/api/teacher/student/:studentId/report', protect, async (req, res) => {
    try {
        const { studentId } = req.params;
        const { academic_year_id, term } = req.query;

        const [students] = await db.execute(`
            SELECT s.*, c.name as classroom_name, c.level, u.name as homeroom_teacher_name
            FROM students s
            JOIN classrooms c ON s.classroom_id = c.id
            LEFT JOIN users u ON c.homeroom_teacher_id = u.id
            WHERE s.id = ?`, [studentId]);

        if (students.length === 0) return res.status(404).json({ message: 'Santri tidak ditemukan.' });
        const student = students[0];

        // Get grades
        let gradesSql = `
            SELECT sg.*, sub.name as subject_name, u.name as teacher_name, ce.name as exam_name
            FROM student_grades sg
            JOIN subjects sub ON sg.subject_id = sub.id
            LEFT JOIN users u ON sg.teacher_id = u.id
            LEFT JOIN classroom_exams ce ON sg.classroom_exam_id = ce.id
            WHERE sg.student_id = ?`;
        const params = [studentId];

        if (academic_year_id) { gradesSql += ' AND sg.academic_year_id = ?'; params.push(academic_year_id); }
        if (term) { gradesSql += ' AND sg.term = ?'; params.push(term); }
        gradesSql += ' ORDER BY sub.name, sg.type';

        const [grades] = await db.execute(gradesSql, params);

        // Group grades by subject
        const subjectGrades = {};
        grades.forEach(g => {
            if (!subjectGrades[g.subject_id]) {
                subjectGrades[g.subject_id] = {
                    subject_id: g.subject_id,
                    subject_name: g.subject_name,
                    teacher_name: g.teacher_name,
                    scores: []
                };
            }
            subjectGrades[g.subject_id].scores.push({
                type: g.type, score: g.score, note: g.note, exam_name: g.exam_name
            });
        });

        // Calculate average per subject
        Object.values(subjectGrades).forEach(sub => {
            const avg = sub.scores.reduce((a, b) => a + Number(b.score), 0) / sub.scores.length;
            sub.average = Math.round(avg * 10) / 10;
        });

        // Attendance
        const [attendance] = await db.execute(`
            SELECT 
                SUM(a.status = 'hadir') as hadir,
                SUM(a.status = 'izin') as izin,
                SUM(a.status = 'sakit') as sakit,
                SUM(a.status = 'alpa') as alpa,
                COUNT(*) as total
            FROM attendances a
            JOIN schedules sch ON a.schedule_id = sch.id
            WHERE a.student_id = ? ${academic_year_id ? 'AND sch.academic_year_id IS NULL' : ''}`,
            [studentId]
        );

        // Class history for promotion check
        const [classHistory] = await db.execute(`
            SELECT ch.*, c.name as classroom_name, ay.name as academic_year_name
            FROM student_class_histories ch
            JOIN classrooms c ON ch.classroom_id = c.id
            JOIN academic_years ay ON ch.academic_year_id = ay.id
            WHERE ch.student_id = ?
            ORDER BY ay.name DESC`, [studentId]);

        res.json({
            student,
            subjects: Object.values(subjectGrades),
            attendance: attendance[0],
            classHistory
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error' });
    }
});

// POST - Publish Report Card (raport) for a student
app.post('/api/teacher/student/:studentId/publish-report', protect, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { studentId } = req.params;
        const { academic_year_id, semester, note, final_grade } = req.body;
        const userId = req.user.id;

        // Check if wali kelas
        const [cls] = await connection.execute(`
            SELECT c.id FROM classrooms c
            JOIN students s ON s.classroom_id = c.id
            WHERE c.homeroom_teacher_id = ? AND s.id = ?`,
            [userId, studentId]
        );
        if (cls.length === 0) {
            await connection.rollback();
            return res.status(403).json({ message: 'Anda bukan wali kelas santri ini.' });
        }

        // Calculate average across all subjects for this term
        const [grades] = await connection.execute(`
            SELECT sg.subject_id, AVG(sg.score) as subject_avg
            FROM student_grades sg
            WHERE sg.student_id = ? AND sg.academic_year_id = ? AND sg.term = ?
            GROUP BY sg.subject_id`, [studentId, academic_year_id, semester]);

        const overallAvg = grades.length > 0
            ? grades.reduce((sum, g) => sum + Number(g.subject_avg), 0) / grades.length
            : 0;

        // Upsert academic_reports per subject
        for (const grade of grades) {
            const [existing] = await connection.execute(
                'SELECT id FROM academic_reports WHERE student_id = ? AND academic_year_id = ? AND semester = ? AND subject_id = ?',
                [studentId, academic_year_id, semester, grade.subject_id]
            );

            if (existing.length > 0) {
                await connection.execute(
                    'UPDATE academic_reports SET grade = ?, note = ?, updated_at = NOW() WHERE id = ?',
                    [Math.round(grade.subject_avg * 10) / 10, note || null, existing[0].id]
                );
            } else {
                await connection.execute(`
                    INSERT INTO academic_reports (student_id, academic_year_id, semester, subject_id, grade, note, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                    [studentId, academic_year_id, semester, grade.subject_id,
                        Math.round(grade.subject_avg * 10) / 10, note || null]
                );
            }
        }

        await connection.commit();

        // Notify parent (if student has parent)
        const [studentData] = await db.execute('SELECT s.*, u.id as parent_user_id FROM students s LEFT JOIN users u ON u.phone = s.parent_phone WHERE s.id = ?', [studentId]);
        if (studentData[0]?.parent_user_id) {
            await createNotification(
                studentData[0].parent_user_id, 'academic', 'Raport Terbit',
                `Raport ${studentData[0].name} semester ${semester} telah diterbitkan oleh wali kelas.`,
                { student_id: parseInt(studentId), academic_year_id }
            );
        }

        res.json({
            message: 'Raport berhasil diterbitkan.',
            overall_average: Math.round(overallAvg * 10) / 10,
            subjects_updated: grades.length
        });
    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal menerbitkan raport.' });
    } finally {
        connection.release();
    }
});

// POST - Promotion decision (naik kelas / tidak naik)
app.post('/api/teacher/student/:studentId/promote', protect, async (req, res) => {
    const connection = await db.getConnection();
    await connection.beginTransaction();
    try {
        const { studentId } = req.params;
        const { is_promoted, next_classroom_id, academic_year_id, decision_note } = req.body;
        const userId = req.user.id;

        // Verify wali kelas
        const [cls] = await connection.execute(`
            SELECT c.id, c.name as current_class_name
            FROM classrooms c
            JOIN students s ON s.classroom_id = c.id
            WHERE c.homeroom_teacher_id = ? AND s.id = ?`,
            [userId, studentId]
        );
        if (cls.length === 0) {
            await connection.rollback();
            return res.status(403).json({ message: 'Anda bukan wali kelas santri ini.' });
        }

        const currentClass = cls[0];

        // Add class history record
        await connection.execute(`
            INSERT INTO student_class_histories 
                (student_id, classroom_id, academic_year_id, is_promoted, homeroom_decision_note, note, start_date, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURDATE(), NOW(), NOW())`,
            [studentId, currentClass.id, academic_year_id || null,
                is_promoted ? 1 : 0, decision_note || null,
                is_promoted ? `Naik kelas dari ${currentClass.current_class_name}` : `Tidak naik kelas, tetap di ${currentClass.current_class_name}`]
        );

        // If promoted and next_classroom_id provided, move student
        if (is_promoted && next_classroom_id) {
            await connection.execute(
                'UPDATE students SET classroom_id = ? WHERE id = ?',
                [next_classroom_id, studentId]
            );
        }

        await connection.commit();

        // Notify parent
        const [studentData] = await db.execute(
            'SELECT s.name, u.id as parent_user_id FROM students s LEFT JOIN users u ON u.phone = s.parent_phone WHERE s.id = ?',
            [studentId]
        );
        if (studentData[0]?.parent_user_id) {
            const msg = is_promoted
                ? `Selamat! ${studentData[0].name} dinyatakan NAIK KELAS oleh wali kelas.`
                : `${studentData[0].name} dinyatakan TIDAK NAIK KELAS. Silakan hubungi wali kelas untuk informasi lebih lanjut.`;
            await createNotification(studentData[0].parent_user_id, 'academic', 'Keputusan Kenaikan Kelas', msg, { student_id: parseInt(studentId) });
        }

        res.json({
            message: is_promoted ? 'Santri dinyatakan naik kelas.' : 'Santri dinyatakan tidak naik kelas.',
            is_promoted,
            next_classroom_id: is_promoted ? next_classroom_id : null
        });
    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: 'Gagal memproses keputusan naik kelas.' });
    } finally {
        connection.release();
    }
});

app.get('/api/teacher/subjects', protect, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT id, name FROM subjects ORDER BY name ASC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// GET - All classrooms for move-to selection (naik kelas)
app.get('/api/teacher/classrooms', protect, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT id, name, level FROM classrooms ORDER BY level, name'
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Secure Server is Healthy', xendit: !!process.env.XENDIT_SECRET_KEY ? 'live' : 'demo' });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  XENPLATFORM SAAS ROUTES (ONBOARDING, PAYOUT, SPLIT INVOICE)
// ═══════════════════════════════════════════════════════════════════════════════
const { createPesantrenSubAccount, createSplitPaymentInvoice, withdrawPesantrenBalance } = require('./xenditService');

app.post('/api/platform/onboard', async (req, res) => {
    try {
        const { email, name } = req.body;
        if (!email || !name) return res.status(400).json({ message: 'Email dan nama pesantren diperlukan' });

        const subAcc = await createPesantrenSubAccount(email, name);
        res.json({ message: 'Sub-account berhasil dibuat', data: subAcc });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message || 'Gagal' });
    }
});

app.post('/api/platform/invoice', protect, async (req, res) => {
    try {
        const { subAccountId, transactionId, totalAmount, platformFee, description, payerEmail } = req.body;
        const invoice = await createSplitPaymentInvoice(subAccountId, { transactionId, totalAmount, platformFee, description, payerEmail });
        res.json({ invoice_url: invoice.invoice_url, external_id: transactionId, xendit_id: invoice.id });
    } catch (err) {
        res.status(500).json({ error: 'Gagal membuat split payment invoice.' });
    }
});

app.post('/api/platform/payout', protect, async (req, res) => {
    try {
        const { subAccountId, referenceId, bankCode, accountName, accountNumber, amount } = req.body;
        const disbursement = await withdrawPesantrenBalance(subAccountId, { referenceId, bankCode, accountName, accountNumber, amount });
        res.json({ message: 'Penarikan diproses', data: disbursement });
    } catch (err) {
        res.status(500).json({ error: err.message || 'Gagal' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SUPER API - XENPLATFORM MANAGEMENT (Only for You)
// ═══════════════════════════════════════════════════════════════════════════════

// Internal Middleware for Super API
const protectSuper = (req, res, next) => {
    const superKey = req.headers['x-super-key'];
    if (superKey && superKey === process.env.ADMIN_API_KEY) {
        return next();
    }
    res.status(401).json({ message: 'Unauthorized. Super Key required.' });
};

// Update Pesantren Platform Fee (Manage via API only)
app.patch('/api/super/pesantren/:id/fee', protectSuper, async (req, res) => {
    try {
        const { id } = req.params;
        const { platform_fee } = req.body;

        if (platform_fee === undefined) return res.status(400).json({ message: 'platform_fee is required' });

        await db.execute('UPDATE pesantrens SET platform_fee = ? WHERE id = ?', [platform_fee, id]);

        res.json({ message: `Success update platform fee for Pesantren #${id} to ${platform_fee}` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Set Xendit Sub-Account ID for Pesantren
app.patch('/api/super/pesantren/:id/xendit', protectSuper, async (req, res) => {
    try {
        const { id } = req.params;
        const { sub_account_id } = req.body;

        if (!sub_account_id) return res.status(400).json({ message: 'sub_account_id is required' });

        await db.execute('UPDATE pesantrens SET xendit_sub_account_id = ?, xendit_status = "active" WHERE id = ?', [sub_account_id, id]);

        res.json({ message: `Success update Sub-Account ID for Pesantren #${id}` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// List all Pesantrens for monitoring
app.get('/api/super/pesantrens', protectSuper, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM pesantrens');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// View Student Usage Logs for Billing
app.get('/api/super/usage-logs', protectSuper, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT ul.*, p.name as pesantren_name 
            FROM usage_logs ul
            JOIN pesantrens p ON ul.pesantren_id = p.id
            ORDER BY ul.date DESC, ul.id DESC
            LIMIT 100
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`\x1b[32m🚀 Server running on http://localhost:${PORT}\x1b[0m`);
    console.log(`Xendit mode: ${process.env.XENDIT_SECRET_KEY ? 'LIVE' : 'DEMO (simulasi)'}`);
});

// ─── Unhandled Error Handlers ───────────────────────────────────────────────────
// These prevent the server from crashing silently and help with debugging
process.on('unhandledRejection', (err) => {
    console.error('\x1b[31m[CRITICAL] Unhandled Rejection:\x1b[0m', err);
    // On production, we might want to restart here, but PM2 handles that.
});

process.on('uncaughtException', (err) => {
    console.error('\x1b[31m[CRITICAL] Uncaught Exception:\x1b[0m', err);
    // Note: It's generally safer to exit after an uncaughtException
    // process.exit(1); 
});

