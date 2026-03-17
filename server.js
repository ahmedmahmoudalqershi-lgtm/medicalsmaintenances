const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-secret-key-change-it'; // يجب تخزينها في متغير بيئي في الإنتاج

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // لخدمة الملفات الثابتة
app.use('/uploads', express.static('uploads')); // لخدمة الملفات المرفوعة



const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
    }
});

// تفعيل قيود المفاتيح الخارجية
db.run('PRAGMA foreign_keys = ON');






function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}



const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        const filetypes = /pdf|jpeg|jpg|png/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only PDF, JPG, JPEG, PNG files are allowed'));
        }
    }
});



function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Forbidden: insufficient permissions' });
        }
        next();
    };
}



app.post('/api/register', async (req, res) => {
    const { email, password, role } = req.body;
    if (!email || !password || !role) {
        return res.status(400).json({ error: 'Email, password, and role are required' });
    }
    if (!['hospital', 'engineer', 'admin'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }

    try {
        // التحقق من وجود البريد
        const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await dbRun(
            'INSERT INTO users (email, password_hash, role, status) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, role, 'pending']
        );
        const userId = result.lastID;

        // إنشاء token
        const token = jwt.sign({ id: userId, email, role }, SECRET_KEY, { expiresIn: '7d' });

        res.status(201).json({ message: 'User registered successfully', userId, token, role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});



app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    try {
        const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            SECRET_KEY,
            { expiresIn: '7d' }
        );

        res.json({ message: 'Login successful', token, role: user.role, status: user.status });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});



app.get('/api/me', authenticateToken, async (req, res) => {

    try {
        const user = await dbGet('SELECT id, email, role, status, created_at FROM users WHERE id = ?', [req.user.id]);
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});


app.post('/api/hospital/profile', authenticateToken, authorizeRole('hospital'), upload.single('commercial_registration'), async (req, res) => {
    const { hospital_name, address, city, phone } = req.body;
    const userId = req.user.id;

    if (!hospital_name || !address || !city || !phone) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    let fileUrl = null;
    if (req.file) {
        fileUrl = `/uploads/${req.file.filename}`;
    }

    try {
        // التحقق من وجود ملف تعريف سابق (ربما تم إنشاؤه مسبقاً)
        const existing = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [userId]);
        if (existing) {
            // تحديث
            await dbRun(
                `UPDATE hospital_profiles SET hospital_name = ?, address = ?, city = ?, phone = ?, commercial_registration_file_url = COALESCE(?, commercial_registration_file_url) WHERE user_id = ?`,
                [hospital_name, address, city, phone, fileUrl, userId]
            );
        } else {
            // إدراج
            await dbRun(
                `INSERT INTO hospital_profiles (user_id, hospital_name, address, city, phone, commercial_registration_file_url) VALUES (?, ?, ?, ?, ?, ?)`,
                [userId, hospital_name, address, city, phone, fileUrl]
            );
        }

        res.json({ message: 'Profile updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/engineer/profile', authenticateToken, authorizeRole('engineer'), upload.fields([{ name: 'certification' }, { name: 'national_id' }]), async (req, res) => {
    const { full_name, phone, specialization, years_experience } = req.body;
    const userId = req.user.id;

    if (!full_name || !phone || !specialization) {
        return res.status(400).json({ error: 'Full name, phone, and specialization are required' });
    }

    let certificationUrl = null;
    let nationalIdUrl = null;
    if (req.files) {
        if (req.files['certification']) {
            certificationUrl = `/uploads/${req.files['certification'][0].filename}`;
        }
        if (req.files['national_id']) {
            nationalIdUrl = `/uploads/${req.files['national_id'][0].filename}`;
        }
    }

    try {
        const existing = await dbGet('SELECT id FROM engineer_profiles WHERE user_id = ?', [userId]);
        if (existing) {
            await dbRun(
                `UPDATE engineer_profiles SET full_name = ?, phone = ?, specialization = ?, years_experience = ?, certification_file_url = COALESCE(?, certification_file_url), national_id_file_url = COALESCE(?, national_id_file_url) WHERE user_id = ?`,
                [full_name, phone, specialization, years_experience, certificationUrl, nationalIdUrl, userId]
            );
        } else {
            await dbRun(
                `INSERT INTO engineer_profiles (user_id, full_name, phone, specialization, years_experience, certification_file_url, national_id_file_url) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [userId, full_name, phone, specialization, years_experience, certificationUrl, nationalIdUrl]
            );
        }

        res.json({ message: 'Profile updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});




app.get('/api/hospital/profile', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    try {
        const profile = await dbGet('SELECT * FROM hospital_profiles WHERE user_id = ?', [req.user.id]);
        res.json(profile || {});
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});
app.get('/api/engineer/profile', authenticateToken, authorizeRole('engineer'), async (req, res) => {
    try {
        const profile = await dbGet('SELECT * FROM engineer_profiles WHERE user_id = ?', [req.user.id]);
        res.json(profile || {});
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});



app.post('/api/devices', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    const { device_name, model, serial_number, manufacturer, last_maintenance_date, status, specialization } = req.body;
    const userId = req.user.id;

    // الحصول على hospital_id من جدول hospital_profiles
    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [userId]);
        if (!hospital) {
            return res.status(400).json({ error: 'Hospital profile not completed' });
        }
        const hospitalId = hospital.id;

        const result = await dbRun(
            `INSERT INTO devices (hospital_id, device_name, model, serial_number, manufacturer, last_maintenance_date, status, specialization)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [hospitalId, device_name, model, serial_number, manufacturer, last_maintenance_date || null, status || 'operational', specialization || 'general']
        );

        res.status(201).json({ message: 'Device added', deviceId: result.lastID });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});



app.get('/api/devices', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [req.user.id]);
        if (!hospital) return res.json([]);
        const devices = await dbAll('SELECT * FROM devices WHERE hospital_id = ?', [hospital.id]);
        res.json(devices);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});



app.put('/api/devices/:id', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    const deviceId = req.params.id;
    const updates = req.body;
    const userId = req.user.id;

    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [userId]);
        if (!hospital) return res.status(403).json({ error: 'No hospital profile' });

        // التحقق أن الجهاز يتبع هذا المستشفى
        const device = await dbGet('SELECT * FROM devices WHERE id = ? AND hospital_id = ?', [deviceId, hospital.id]);
        if (!device) return res.status(404).json({ error: 'Device not found or not owned' });

        // بناء استعلام التحديث ديناميكياً
        const fields = [];
        const values = [];
        for (let key in updates) {
            if (updates.hasOwnProperty(key) && key !== 'id' && key !== 'hospital_id' && key !== 'created_at') {
                fields.push(`${key} = ?`);
                values.push(updates[key]);
            }
        }
        if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
        values.push(deviceId);
        const query = `UPDATE devices SET ${fields.join(', ')} WHERE id = ?`;
        await dbRun(query, values);
        res.json({ message: 'Device updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.delete('/api/devices/:id', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    const deviceId = req.params.id;
    const userId = req.user.id;
    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [userId]);
        if (!hospital) return res.status(403).json({ error: 'No hospital profile' });

        const device = await dbGet('SELECT id FROM devices WHERE id = ? AND hospital_id = ?', [deviceId, hospital.id]);
        if (!device) return res.status(404).json({ error: 'Device not found' });

        await dbRun('DELETE FROM devices WHERE id = ?', [deviceId]);
        res.json({ message: 'Device deleted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});


app.post('/api/requests', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    const { device_id, title, description, urgency } = req.body;
    if (!device_id || !title || !description) {
        return res.status(400).json({ error: 'Device, title, and description required' });
    }

    const userId = req.user.id;
    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [userId]);
        if (!hospital) return res.status(400).json({ error: 'Hospital profile not found' });

        // التحقق من أن الجهاز يتبع المستشفى
        const device = await dbGet('SELECT id FROM devices WHERE id = ? AND hospital_id = ?', [device_id, hospital.id]);
        if (!device) return res.status(404).json({ error: 'Device not found or not owned' });

        const result = await dbRun(
            `INSERT INTO maintenance_requests (hospital_id, device_id, title, description, urgency)
             VALUES (?, ?, ?, ?, ?)`,
            [hospital.id, device_id, title, description, urgency || 'medium']
        );

        // إنشاء إشعار للمشرفين (أو للمهندسين المهتمين) - سيتم لاحقاً
        // يمكن إرسال إشعار لجميع المهندسين المتخصصين (حسب specialization) لكن هذا يحتاج لجدولة.

        res.status(201).json({ message: 'Request created', requestId: result.lastID });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/requests/hospital', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [req.user.id]);
        if (!hospital) return res.json([]);
        const requests = await dbAll('SELECT * FROM maintenance_requests WHERE hospital_id = ? ORDER BY created_at DESC', [hospital.id]);
        res.json(requests);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});




app.get('/api/requests/open', authenticateToken, authorizeRole('engineer'), async (req, res) => {
    try {
        const requests = await dbAll(`
            SELECT mr.*, d.device_name, d.model, d.specialization, h.hospital_name, h.city
            FROM maintenance_requests mr
            JOIN devices d ON mr.device_id = d.id
            JOIN hospital_profiles h ON mr.hospital_id = h.id
            WHERE mr.status = 'open'
            ORDER BY 
                CASE mr.urgency
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END, mr.created_at ASC
        `);
        res.json(requests);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});



app.post('/api/bids', authenticateToken, authorizeRole('engineer'), async (req, res) => {
    const { request_id, price, estimated_days, description } = req.body;
    if (!request_id || !price || !estimated_days) {
        return res.status(400).json({ error: 'Request ID, price, and estimated days required' });
    }

    const engineerId = req.user.id;
    try {
        const engineer = await dbGet('SELECT id FROM engineer_profiles WHERE user_id = ?', [engineerId]);
        if (!engineer) return res.status(400).json({ error: 'Engineer profile not found' });

        // التحقق من أن الطلب موجود وما زال مفتوحاً
        const request = await dbGet('SELECT status FROM maintenance_requests WHERE id = ?', [request_id]);
        if (!request) return res.status(404).json({ error: 'Request not found' });
        if (request.status !== 'open') return res.status(400).json({ error: 'Request is not open for bidding' });

        // التحقق من عدم وجود عرض سابق من نفس المهندس على نفس الطلب (unique constraint)
        try {
            const result = await dbRun(
                `INSERT INTO bids (request_id, engineer_id, price, estimated_days, description)
                 VALUES (?, ?, ?, ?, ?)`,
                [request_id, engineer.id, price, estimated_days, description || null]
            );
            res.status(201).json({ message: 'Bid submitted', bidId: result.lastID });
        } catch (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(400).json({ error: 'You have already bid on this request' });
            }
            throw err;
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});



app.post('/api/bids/:bidId/reject', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    const bidId = req.params.bidId;
    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [req.user.id]);
        if (!hospital) return res.status(403).json({ error: 'Hospital profile not found' });

        const bid = await dbGet(`
            SELECT b.*, mr.hospital_id
            FROM bids b
            JOIN maintenance_requests mr ON b.request_id = mr.id
            WHERE b.id = ?
        `, [bidId]);
        if (!bid) return res.status(404).json({ error: 'Bid not found' });
        if (bid.hospital_id !== hospital.id) return res.status(403).json({ error: 'Not your request' });
        if (bid.status !== 'pending') return res.status(400).json({ error: 'Bid is not pending' });

        await dbRun('UPDATE bids SET status = ? WHERE id = ?', ['rejected', bidId]);
        res.json({ message: 'Bid rejected' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});


app.post('/api/bids/:bidId/withdraw', authenticateToken, authorizeRole('engineer'), async (req, res) => {
    const bidId = req.params.bidId;
    try {
        const engineer = await dbGet('SELECT id FROM engineer_profiles WHERE user_id = ?', [req.user.id]);
        if (!engineer) return res.status(403).json({ error: 'Engineer profile not found' });

        const bid = await dbGet('SELECT * FROM bids WHERE id = ? AND engineer_id = ?', [bidId, engineer.id]);
        if (!bid) return res.status(404).json({ error: 'Bid not found' });
        if (bid.status !== 'pending') return res.status(400).json({ error: 'Can only withdraw pending bids' });

        await dbRun('UPDATE bids SET status = ? WHERE id = ?', ['withdrawn', bidId]);
        res.json({ message: 'Bid withdrawn' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});



app.put('/api/requests/:requestId/status', authenticateToken, authorizeRole('engineer'), async (req, res) => {
    const requestId = req.params.requestId;
    const { status } = req.body;
    if (!['in_progress', 'completed', 'cancelled'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    try {
        const engineer = await dbGet('SELECT id FROM engineer_profiles WHERE user_id = ?', [req.user.id]);
        if (!engineer) return res.status(403).json({ error: 'Engineer profile not found' });

        const request = await dbGet('SELECT assigned_engineer_id, status FROM maintenance_requests WHERE id = ?', [requestId]);
        if (!request) return res.status(404).json({ error: 'Request not found' });
        if (request.assigned_engineer_id !== engineer.id) return res.status(403).json({ error: 'You are not assigned to this request' });

        // منطق الانتقال المسموح: من assigned إلى in_progress، من in_progress إلى completed
        if (request.status === 'assigned' && status === 'in_progress') {
            await dbRun('UPDATE maintenance_requests SET status = ? WHERE id = ?', [status, requestId]);
        } else if (request.status === 'in_progress' && status === 'completed') {
            await dbRun('UPDATE maintenance_requests SET status = ? WHERE id = ?', [status, requestId]);
            // يمكن إضافة منطق لتحديث آخر صيانة للجهاز
        } else {
            return res.status(400).json({ error: 'Invalid status transition' });
        }

        res.json({ message: 'Request status updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});



app.post('/api/reviews', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    const { request_id, rating, comment } = req.body;
    if (!request_id || !rating || rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Request ID and rating (1-5) required' });
    }

    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [req.user.id]);
        if (!hospital) return res.status(403).json({ error: 'Hospital profile not found' });

        // التحقق من أن الطلب مكتمل ويخص هذا المستشفى
        const request = await dbGet(`
            SELECT mr.*, mr.assigned_engineer_id 
            FROM maintenance_requests mr
            WHERE mr.id = ? AND mr.hospital_id = ? AND mr.status = 'completed'
        `, [request_id, hospital.id]);
        if (!request) return res.status(404).json({ error: 'Completed request not found' });

        // التحقق من عدم وجود تقييم مسبق
        const existing = await dbGet('SELECT id FROM reviews WHERE request_id = ?', [request_id]);
        if (existing) return res.status(400).json({ error: 'Review already exists for this request' });

        // إضافة التقييم
        await dbRun(
            `INSERT INTO reviews (request_id, hospital_id, engineer_id, rating, comment)
             VALUES (?, ?, ?, ?, ?)`,
            [request_id, hospital.id, request.assigned_engineer_id, rating, comment || null]
        );

        // تحديث متوسط تقييم المهندس وإجمالي الوظائف
        // يمكن عمل استعلام لحساب المتوسط
        const engineerId = request.assigned_engineer_id;
        const stats = await dbGet(
            `SELECT AVG(rating) as avgRating, COUNT(*) as total FROM reviews WHERE engineer_id = ?`,
            [engineerId]
        );
        await dbRun(
            `UPDATE engineer_profiles SET rating = ?, total_jobs = ? WHERE id = ?`,
            [stats.avgRating || 0, stats.total, engineerId]
        );

        res.status(201).json({ message: 'Review added' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});


async function createNotification(userId, message, type = 'general') {
    try {
        await dbRun('INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)', [userId, message, type]);
    } catch (err) {
        console.error('Failed to create notification:', err);
    }
}

app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const notifications = await dbAll(
            'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
            [req.user.id]
        );
        res.json(notifications);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
    const notifId = req.params.id;
    try {
        await dbRun('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?', [notifId, req.user.id]);
        res.json({ message: 'Notification marked as read' });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const users = await dbAll(`
            SELECT u.id, u.email, u.role, u.status, u.created_at,
                   hp.hospital_name, ep.full_name
            FROM users u
            LEFT JOIN hospital_profiles hp ON u.id = hp.user_id
            LEFT JOIN engineer_profiles ep ON u.id = ep.user_id
            ORDER BY u.created_at DESC
        `);
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});


app.put('/api/admin/users/:userId/status', authenticateToken, authorizeRole('admin'), async (req, res) => {
    const userId = req.params.userId;
    const { status } = req.body;
    if (!['verified', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    try {
        // تحديث حالة المستخدم
        await dbRun('UPDATE users SET status = ? WHERE id = ?', [status, userId]);
        // إذا كان verified، نضع verified_at في الجدول المختص
        if (status === 'verified') {
            // التحقق من الدور
            const user = await dbGet('SELECT role FROM users WHERE id = ?', [userId]);
            if (user) {
                if (user.role === 'hospital') {
                    await dbRun('UPDATE hospital_profiles SET verified_at = CURRENT_TIMESTAMP WHERE user_id = ?', [userId]);
                } else if (user.role === 'engineer') {
                    await dbRun('UPDATE engineer_profiles SET verified_at = CURRENT_TIMESTAMP WHERE user_id = ?', [userId]);
                }
            }
        }
        res.json({ message: 'User status updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});



app.get('/api/admin/requests', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const requests = await dbAll(`
            SELECT mr.*, d.device_name, h.hospital_name, e.full_name as engineer_name
            FROM maintenance_requests mr
            JOIN devices d ON mr.device_id = d.id
            JOIN hospital_profiles h ON mr.hospital_id = h.id
            LEFT JOIN engineer_profiles e ON mr.assigned_engineer_id = e.id
            ORDER BY mr.created_at DESC
        `);
        res.json(requests);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});




// =============== مسارات المهندس الإضافية ===============
// --- مسارات المهندس الموحدة والآمنة ---

// 1. الطلبات المفتوحة (تعمل للكل)



// =============== مسارات المشرف ===============
app.get('/api/admin/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const users = await dbAll(`
            SELECT u.id, u.email, u.role, u.status, u.created_at,
                   hp.hospital_name, ep.full_name
            FROM users u
            LEFT JOIN hospital_profiles hp ON u.id = hp.user_id
            LEFT JOIN engineer_profiles ep ON u.id = ep.user_id
            ORDER BY u.created_at DESC
        `);
        res.json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.put('/api/admin/users/:userId/status', authenticateToken, authorizeRole('admin'), async (req, res) => {
    const userId = req.params.userId;
    const { status } = req.body;
    if (!['verified', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    try {
        await dbRun('UPDATE users SET status = ? WHERE id = ?', [status, userId]);
        if (status === 'verified') {
            const user = await dbGet('SELECT role FROM users WHERE id = ?', [userId]);
            if (user) {
                if (user.role === 'hospital') {
                    await dbRun('UPDATE hospital_profiles SET verified_at = CURRENT_TIMESTAMP WHERE user_id = ?', [userId]);
                } else if (user.role === 'engineer') {
                    await dbRun('UPDATE engineer_profiles SET verified_at = CURRENT_TIMESTAMP WHERE user_id = ?', [userId]);
                }
            }
        }
        res.json({ message: 'User status updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/requests', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const requests = await dbAll(`
            SELECT mr.*, d.device_name, h.hospital_name, e.full_name as engineer_name
            FROM maintenance_requests mr
            JOIN devices d ON mr.device_id = d.id
            JOIN hospital_profiles h ON mr.hospital_id = h.id
            LEFT JOIN engineer_profiles e ON mr.assigned_engineer_id = e.id
            ORDER BY mr.created_at DESC
        `);
        res.json(requests);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// =============== تحديث مسار الطلبات المفتوحة ليشمل معلومات أكثر ===============
app.get('/api/requests/open', authenticateToken, authorizeRole('engineer'), async (req, res) => {
    try {
        const requests = await dbAll(`
            SELECT mr.*, d.device_name, d.model, d.specialization, h.hospital_name, h.city
            FROM maintenance_requests mr
            JOIN devices d ON mr.device_id = d.id
            JOIN hospital_profiles h ON mr.hospital_id = h.id
            WHERE mr.status = 'open'
            ORDER BY 
                CASE mr.urgency
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END, mr.created_at ASC
        `);
        res.json(requests);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// =============== تحديث مسار طلبات المستشفى ليشمل اسم الجهاز ===============
app.get('/api/requests/hospital', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [req.user.id]);
        if (!hospital) return res.json([]);
        const requests = await dbAll(`
            SELECT mr.*, d.device_name
            FROM maintenance_requests mr
            JOIN devices d ON mr.device_id = d.id
            WHERE mr.hospital_id = ?
            ORDER BY mr.created_at DESC
        `, [hospital.id]);
        res.json(requests);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});











// =============== مسارات المهندس ===============

// عرض الطلبات المفتوحة (التي لم يعين لها مهندس)
app.get('/api/requests/open', authenticateToken, authorizeRole('engineer'), async (req, res) => {
    try {
        const requests = await dbAll(`
            SELECT mr.*, d.device_name, d.model, d.specialization, h.hospital_name, h.city
            FROM maintenance_requests mr
            JOIN devices d ON mr.device_id = d.id
            JOIN hospital_profiles h ON mr.hospital_id = h.id
            WHERE mr.status = 'open'
            ORDER BY 
                CASE mr.urgency
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END, mr.created_at ASC
        `);
        res.json(requests);
    } catch (err) {
        console.error('Error in /api/requests/open:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// عرض الطلبات الموكلة للمهندس الحالي
app.get('/api/requests/engineer', authenticateToken, authorizeRole('engineer'), async (req, res) => {
    try {
        // الحصول على engineer_id من جدول engineer_profiles المرتبط بالمستخدم
        const engineer = await dbGet('SELECT id FROM engineer_profiles WHERE user_id = ?', [req.user.id]);
        if (!engineer) {
            return res.status(400).json({ error: 'لم يتم إكمال الملف الشخصي للمهندس بعد' });
        }

        const requests = await dbAll(`
            SELECT mr.*, d.device_name, d.model, h.hospital_name
            FROM maintenance_requests mr
            JOIN devices d ON mr.device_id = d.id
            JOIN hospital_profiles h ON mr.hospital_id = h.id
            WHERE mr.assigned_engineer_id = ?
            ORDER BY mr.created_at DESC
        `, [engineer.id]);
        res.json(requests);
    } catch (err) {
        console.error('Error in /api/requests/engineer:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// عرض العروض التي قدمها المهندس
app.get('/api/bids/engineer', authenticateToken, authorizeRole('engineer'), async (req, res) => {
    try {
        const engineer = await dbGet('SELECT id FROM engineer_profiles WHERE user_id = ?', [req.user.id]);
        if (!engineer) {
            return res.status(400).json({ error: 'لم يتم إكمال الملف الشخصي للمهندس بعد' });
        }

        const bids = await dbAll(`
            SELECT b.*, mr.title as request_title
            FROM bids b
            JOIN maintenance_requests mr ON b.request_id = mr.id
            WHERE b.engineer_id = ?
            ORDER BY b.created_at DESC
        `, [engineer.id]);
        res.json(bids);
    } catch (err) {
        console.error('Error in /api/bids/engineer:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});






// 1. جلب العروض الخاصة بطلب معين (يستخدمه المستشفى)
app.get('/api/requests/:requestId/bids', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    try {
        const requestId = req.params.requestId;
        // التأكد أولاً أن الطلب يخص هذا المستشفى
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [req.user.id]);
        const request = await dbGet('SELECT id FROM maintenance_requests WHERE id = ? AND hospital_id = ?', [requestId, hospital.id]);

        if (!request) return res.status(403).json({ error: 'غير مسموح لك بالوصول لهذا الطلب' });

        const bids = await dbAll(`
            SELECT b.*, ep.full_name, ep.rating 
            FROM bids b 
            JOIN engineer_profiles ep ON b.engineer_id = ep.id 
            WHERE b.request_id = ?
        `, [requestId]);
        
        res.json(bids);
    } catch (err) {
        res.status(500).json({ error: 'خطأ في جلب العروض' });
    }
});

// 2. قبول عرض مهندس (Hire)
app.post('/api/bids/:bidId/accept', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    const bidId = req.params.bidId;
    try {
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [req.user.id]);
        
        // جلب بيانات العرض والطلب للتأكد من الملكية
        const bid = await dbGet(`
            SELECT b.*, mr.hospital_id FROM bids b 
            JOIN maintenance_requests mr ON b.request_id = mr.id 
            WHERE b.id = ?`, [bidId]);

        if (!bid || bid.hospital_id !== hospital.id) {
            return res.status(403).json({ error: 'العرض غير موجود أو لا يخصك' });
        }

        // تحديث حالة العرض إلى 'accepted'
        await dbRun('UPDATE bids SET status = ? WHERE id = ?', ['accepted', bidId]);
        
        // تحديث الطلب ليكون 'assigned' وربطه بالمهندس
        await dbRun('UPDATE maintenance_requests SET status = ?, assigned_engineer_id = ? WHERE id = ?', 
            ['assigned', bid.engineer_id, bid.request_id]);

        // رفض باقي العروض تلقائياً لنفس الطلب (اختياري)
        await dbRun('UPDATE bids SET status = ? WHERE request_id = ? AND id != ?', ['rejected', bid.request_id, bidId]);

        res.json({ message: 'تم قبول العرض بنجاح' });
    } catch (err) {
        res.status(500).json({ error: 'فشل في قبول العرض' });
    }
});








// جلب جميع العروض المقدمة على كافة الطلبات الخاصة بالمستشفى
// جلب كافة العروض المقدمة لطلبات هذا المستشفى (للملخص العام)
app.get('/api/bids/hospital', authenticateToken, authorizeRole('hospital'), async (req, res) => {
    try {
        // 1. الحصول على ID المستشفى من ملفه الشخصي
        const hospital = await dbGet('SELECT id FROM hospital_profiles WHERE user_id = ?', [req.user.id]);
        if (!hospital) return res.status(404).json({ error: 'ملف المستشفى غير مكتمل' });

        // 2. استعلام لجلب العروض مع معلومات الجهاز واسم المهندس
        const bids = await dbAll(`
            SELECT 
                b.*, 
                d.device_name, 
                ep.full_name 
            FROM bids b
            JOIN maintenance_requests mr ON b.request_id = mr.id
            JOIN devices d ON mr.device_id = d.id
            JOIN engineer_profiles ep ON b.engineer_id = ep.id
            WHERE mr.hospital_id = ?
            ORDER BY b.created_at DESC
        `, [hospital.id]);

        res.json(bids);
    } catch (err) {
        console.error('Error fetching hospital bids:', err);
        res.status(500).json({ error: 'خطأ في جلب العروض من قاعدة البيانات' });
    }
});








app.use(express.static('public'));







app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
















































