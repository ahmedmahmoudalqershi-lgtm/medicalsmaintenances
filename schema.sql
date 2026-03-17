-- 1. تمكين قيود المفاتيح الخارجية
PRAGMA foreign_keys = ON;

-- 2. جدول المستخدمين
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('hospital', 'engineer', 'admin')) NOT NULL,
    status TEXT CHECK(status IN ('pending', 'verified', 'rejected')) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 3. جدول الملفات الشخصية (اختياري)
CREATE TABLE profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    email TEXT NOT NULL,
    status TEXT CHECK(status IN ('pending', 'verified', 'rejected')) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 4. جدول بيانات المستشفيات
CREATE TABLE hospital_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    hospital_name TEXT NOT NULL,
    address TEXT NOT NULL,
    city TEXT NOT NULL,
    phone TEXT NOT NULL,
    commercial_registration_file_url TEXT,
    verified_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 5. جدول بيانات المهندسين
CREATE TABLE engineer_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    specialization TEXT NOT NULL,
    years_experience INTEGER NOT NULL DEFAULT 0,
    certification_file_url TEXT,
    national_id_file_url TEXT,
    verified_at DATETIME,
    rating REAL DEFAULT 0,
    total_jobs INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 6. جدول الأجهزة
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hospital_id INTEGER NOT NULL,
    device_name TEXT NOT NULL,
    model TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    manufacturer TEXT NOT NULL,
    last_maintenance_date DATE,
    status TEXT CHECK(status IN ('operational', 'needs_maintenance', 'under_repair', 'decommissioned')) DEFAULT 'operational',
    specialization TEXT NOT NULL DEFAULT 'general',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (hospital_id) REFERENCES hospital_profiles(id) ON DELETE CASCADE
);

-- 7. جدول طلبات الصيانة
CREATE TABLE maintenance_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hospital_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    urgency TEXT CHECK(urgency IN ('critical', 'high', 'medium', 'low')) DEFAULT 'medium',
    status TEXT CHECK(status IN ('open', 'assigned', 'in_progress', 'completed', 'cancelled')) DEFAULT 'open',
    assigned_engineer_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (hospital_id) REFERENCES hospital_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_engineer_id) REFERENCES engineer_profiles(id) ON DELETE SET NULL
);

-- 8. جدول العروض
CREATE TABLE bids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    engineer_id INTEGER NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    estimated_days INTEGER NOT NULL,
    description TEXT,
    status TEXT CHECK(status IN ('pending', 'accepted', 'rejected', 'withdrawn')) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(request_id, engineer_id),
    FOREIGN KEY (request_id) REFERENCES maintenance_requests(id) ON DELETE CASCADE,
    FOREIGN KEY (engineer_id) REFERENCES engineer_profiles(id) ON DELETE CASCADE
);

-- 9. جدول الإشعارات
CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    type TEXT DEFAULT 'general',
    is_read BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 10. جدول التقييمات
CREATE TABLE reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    hospital_id INTEGER NOT NULL,
    engineer_id INTEGER NOT NULL,
    rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES maintenance_requests(id) ON DELETE CASCADE,
    FOREIGN KEY (hospital_id) REFERENCES hospital_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY (engineer_id) REFERENCES engineer_profiles(id) ON DELETE CASCADE
);

-- 11. الـ Triggers لتحديث وقت التعديل (Updated At) تلقائياً
CREATE TRIGGER trg_users_updated_at AFTER UPDATE ON users BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER trg_hospital_updated_at AFTER UPDATE ON hospital_profiles BEGIN
    UPDATE hospital_profiles SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER trg_engineer_updated_at AFTER UPDATE ON engineer_profiles BEGIN
    UPDATE engineer_profiles SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER trg_requests_updated_at AFTER UPDATE ON maintenance_requests BEGIN
    UPDATE maintenance_requests SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
