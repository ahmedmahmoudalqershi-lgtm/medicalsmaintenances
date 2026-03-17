// public/js/auth.js

const API_BASE = ''; // يمكن تعديلها إذا كان الخادم على منفذ مختلف

function getToken() {
    return localStorage.getItem('token');
}

function requireAuth() {
    const token = getToken();
    if (!token) {
        window.location.href = '/login.html';
        return false;
    }
    return true;
}

function authHeaders() {
    return {
        'Authorization': `Bearer ${getToken()}`,
        'Content-Type': 'application/json'
    };
}

function authHeadersMultipart() {
    return {
        'Authorization': `Bearer ${getToken()}`
    };
}

async function handleResponse(res) {
    if (res.status === 401) {
        localStorage.removeItem('token');
        window.location.href = '/login.html';
        throw new Error('انتهت الجلسة');
    }
    if (!res.ok) {
        const error = await res.json().catch(() => ({ error: 'خطأ غير معروف' }));
        throw new Error(error.error || 'حدث خطأ');
    }
    return res.json();
}

function logout() {
    localStorage.clear();
    window.location.href = '/login.html';
}

async function getCurrentUser() {
    const res = await fetch('/api/me', { headers: authHeaders() });
    return handleResponse(res);
}