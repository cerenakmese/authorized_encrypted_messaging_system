const API_URL = "/api";
let cachedMessages = [];

// --- AUTH İŞLEMLERİ ---
async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    try {
        const res = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();

        if (data.success) {
            // Giriş başarılıysa Dashboard'a yönlendir
            window.location.href = "/dashboard";
        } else {
            showAlert('error', data.error);
        }
    } catch(err) { console.error(err); }
}

async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    const role = document.getElementById('regRole').value;

    const res = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role })
    });
    const data = await res.json();

    if (data.success) {
        showToast("Kayıt başarılı! Giriş yapabilirsiniz.");
        toggleAuth('login');
    } else {
        showAlert('error', data.error);
    }
}

// --- OTURUM KONTROLÜ VE YÖNLENDİRME ---
async function checkSessionAndRedirect(pageType) {
    try {
        const res = await fetch(`${API_URL}/check_session`);
        const data = await res.json();

        if (!data.logged_in) {
            // Oturum yoksa Login'e at
            window.location.href = "/login";
            return;
        }

        // Kullanıcı adını arayüzde göster
        const userDisplay = document.getElementById('displayUsername');
        if (userDisplay) userDisplay.innerText = `${data.username} (${data.role})`;

        // Eğer Admin sayfasındaysa ve rolü Admin değilse 403'e at
        if (pageType === 'admin' && data.role !== 'Admin') {
            window.location.href = "/403";
        }

        // Eğer Dashboard'daysa ve Admisse, Admin butonunu göster
        if (pageType === 'dashboard' && data.role === 'Admin') {
            const btn = document.getElementById('adminNavBtn');
            if (btn) btn.style.display = 'flex';
        }

        // Sayfa tipine göre verileri çek
        if (pageType === 'dashboard') fetchMessages();
        if (pageType === 'admin') { fetchMessages(); } // Admin logları da mesaj listesinden besleniyor
        
    } catch (e) { console.error("Session hatası", e); }
}

// --- MESAJ İŞLEMLERİ ---
async function sendMessage() {
    const txt = document.getElementById('messageInput');
    if (!txt.value) return showToast("Boş mesaj gönderilemez!");

    const res = await fetch('/send_message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: txt.value })
    });
    const data = await res.json();

    if (data.success) {
        showToast(data.info);
        txt.value = '';
        fetchMessages();
    }
}

async function fetchMessages() {
    try {
        const res = await fetch('/get_messages');
        cachedMessages = await res.json();
        
        // Hangi sayfadaysak ona göre render et
        if (document.getElementById('messagesList')) renderMessages();
        if (document.getElementById('adminLogTableBody')) renderAdminLogs();
        
    } catch (e) {}
}

function renderMessages() {
    const list = document.getElementById('messagesList');
    list.innerHTML = '';

    cachedMessages.forEach((msg, index) => {
        const isEncrypted = msg.status === 'encrypted';
        const iconClass = isEncrypted ? 'fa-lock' : 'fa-lock-open';
        
        // Göz İkonu: Sadece şifresi çözülmüşse (Admin'e) veya Backend ciphertext yolluyorsa
        
        const toggleBtn = (!isEncrypted && msg.ciphertext) 
            ? `<i class="fas fa-eye toggle-decrypt" onclick="toggleCipherView(${index})"></i>` 
            : '';

        const html = `
            <div class="message-card ${msg.status}">
                <div style="display:flex; justify-content:space-between; color:#888; font-size:0.8em;">
                    <span><strong>${msg.sender}</strong> (${msg.role})</span>
                    <span>${msg.timestamp}</span>
                </div>
                <div class="msg-content">
                    <i id="icon-${index}" class="fas ${iconClass} status-icon"></i> 
                    <span id="text-${index}" class="msg-text" data-view="plain">${msg.text}</span>
                    ${toggleBtn}
                </div>
                <div style="margin-top:5px;"><span class="algo-tag">Algoritma: ${msg.algo}</span></div>
            </div>
        `;
        list.innerHTML += html;
    });
}

function renderAdminLogs() {
    const tbody = document.getElementById('adminLogTableBody');
    tbody.innerHTML = '';
    cachedMessages.forEach(m => {
        tbody.innerHTML += `<tr>
            <td>${m.timestamp}</td><td>${m.sender}</td><td>${m.role}</td>
            <td>${m.algo}</td><td>${m.status === 'decrypted' ? '<span style="color:#0f0">Okundu</span>' : '<span style="color:red">Şifreli</span>'}</td>
        </tr>`;
    });
}

// --- GÖZ İKONU (TOGGLE) ---
function toggleCipherView(index) {
    const msg = cachedMessages[index];
    const textSpan = document.getElementById(`text-${index}`);
    const icon = document.getElementById(`icon-${index}`);
    
    if (textSpan.getAttribute('data-view') === 'plain') {
        textSpan.innerText = msg.ciphertext || "Şifreli veri yok";
        textSpan.style.color = '#ff4d4d';
        textSpan.setAttribute('data-view', 'cipher');
        icon.className = 'fas fa-lock status-icon';
    } else {
        textSpan.innerText = msg.text;
        textSpan.style.color = '#e0e0e0';
        textSpan.setAttribute('data-view', 'plain');
        icon.className = 'fas fa-lock-open status-icon';
    }
}

// --- DİĞERLERİ ---
async function logout() {
    await fetch(`${API_URL}/logout`, { method: 'POST' });
    window.location.href = "/login";
}

function toggleAuth(target) {
    if(target === 'register') {
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('registerForm').style.display = 'block';
        document.getElementById('formTitle').innerText = 'Kayıt Ol';
    } else {
        document.getElementById('loginForm').style.display = 'block';
        document.getElementById('registerForm').style.display = 'none';
        document.getElementById('formTitle').innerText = 'Giriş Yap';
    }
}

function showToast(msg) {
    const c = document.getElementById('toast-container');
    const t = document.createElement('div');
    t.className = 'toast';
    t.innerText = msg;
    c.appendChild(t);
    setTimeout(() => t.remove(), 3000);
}

function showAlert(type, msg) {
    const box = document.getElementById('authAlert');
    box.style.display = 'block';
    box.innerText = msg;
    setTimeout(() => box.style.display = 'none', 3000);
}

// Event Listeners (Eğer sayfada form varsa)
if(document.getElementById('loginForm')) {
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    document.getElementById('registerForm').addEventListener('submit', handleRegister);
}