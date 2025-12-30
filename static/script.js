const API_URL = "/api";
let cachedMessages = [];

// --- LOGIN & REGISTER ---
async function handleLogin(e) {
    e.preventDefault();
    const u = document.getElementById('loginUsername').value;
    const p = document.getElementById('loginPassword').value;

    const res = await fetch(`${API_URL}/login`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ username: u, password: p })
    });
    const data = await res.json();

    if (data.success) {
        window.location.href = data.redirect_url;
    } else {
        alert(data.error || "Giriş başarısız.");
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const u = document.getElementById('regUsername').value;
    const p = document.getElementById('regPassword').value;
    const r = document.getElementById('regRole').value;

    const res = await fetch(`${API_URL}/register`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ username: u, password: p, role: r })
    });
    const data = await res.json();

    if (data.success) {
        alert("Kayıt başarılı! Giriş yapabilirsiniz.");
        toggleAuth('login');
    } else {
        alert(data.error);
    }
}

// --- OTURUM KONTROLÜ ---
async function checkSessionAndRedirect(pageType) {
    try {
        const res = await fetch(`${API_URL}/check_session`);
        const data = await res.json();

        if (!data.logged_in) {
            window.location.href = "/login";
            return;
        }

        const userDisplay = document.getElementById('displayUsername');
        if (userDisplay) userDisplay.innerText = `${data.username} (${data.role})`;

        if (pageType === 'admin' && data.role !== 'Admin') {
            window.location.href = "/403";
        }

        if (data.role === 'Admin') {
            const btn = document.getElementById('adminNavBtn');
            if(btn) btn.style.display = 'flex';
        }

        fetchMessages();
    } catch (e) { console.error(e); }
}

// --- GÜNCELLENMİŞ MESAJ GÖNDERME (ROL SEÇİMLİ) ---
async function sendMessage() {
    const txtBox = document.getElementById('messageInput');

    if (!txtBox) {
        alert("HATA: Mesaj kutusu bulunamadı!");
        return;
    }

    const msgValue = txtBox.value.trim();
    if (!msgValue) {
        alert("Boş mesaj gönderemezsin!");
        return;
    }

    // --- YENİ: CHECKBOX'LARDAN ROLLERİ TOPLA ---
    const roles = [];
    if (document.getElementById('roleAdmin').checked) roles.push('Admin');
    if (document.getElementById('roleManager').checked) roles.push('Manager');
    if (document.getElementById('roleUser').checked) roles.push('User');

    if (roles.length === 0) {
        alert("HATA: Mesajı kimin göreceğini seçmelisin! (En az bir kutucuk işaretle)");
        return;
    }

    try {
        const res = await fetch('/send_message', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                message: msgValue,
                allowed_roles: roles // Backend'e listeyi gönderiyoruz
            })
        });

        const data = await res.json();

        if (data.success) {
            txtBox.value = '';
            fetchMessages();
            console.log("Mesaj gitti:", data.info);
        } else {
            alert("HATA: " + data.error);
        }
    } catch (err) {
        console.error("Bağlantı hatası:", err);
    }
}

// --- MESAJLARI GETİRME ---
async function fetchMessages() {
    try {
        const res = await fetch('/get_messages');
        cachedMessages = await res.json();

        if (document.getElementById('messagesList')) renderMessages();
        if (document.getElementById('adminLogTableBody')) renderAdminLogs();
    } catch(e) {}
}

function renderMessages() {
    const list = document.getElementById('messagesList');
    list.innerHTML = '';

    cachedMessages.forEach((msg, index) => {
        const toggleBtn = msg.can_decrypt
            ? `<i class="fas fa-eye toggle-decrypt" onclick="toggleCipherView(${index})" style="cursor:pointer; margin-left:10px;"></i>`
            : '';

        const borderStyle = msg.can_decrypt ? 'border-left: 4px solid #00ff88;' : 'border-left: 4px solid #ff4d4d;';

        // İzin verilen rolleri gösterelim
        const targets = msg.targets ? msg.targets.join(", ") : "Herkes";

        const html = `
            <div class="message-card" style="background:#1e1e1e; padding:15px; margin-bottom:10px; border-radius:4px; ${borderStyle}">
                <div style="display:flex; justify-content:space-between; color:#888; font-size:0.8em;">
                    <span><strong>${msg.sender}</strong> (${msg.role}) -> <i class="fas fa-users"></i> ${targets}</span>
                    <span>${msg.timestamp}</span>
                </div>
                <div class="msg-content" style="margin-top:10px; font-family:'Courier New'; font-size:1.1em; display:flex; align-items:center;">
                    <i id="icon-${index}" class="fas fa-lock" style="color:#ff4d4d; margin-right:10px;"></i>
                    <span id="text-${index}" style="color:#ff4d4d; filter:blur(1px); word-break:break-all;">${msg.ciphertext}</span>
                    ${toggleBtn}
                </div>
                <div style="margin-top:5px; font-size:0.7em; color:#555;">Algo: ${msg.algo}</div>
            </div>
        `;
        list.innerHTML += html;
    });
}

function toggleCipherView(index) {
    const msg = cachedMessages[index];
    const textSpan = document.getElementById(`text-${index}`);
    const icon = document.getElementById(`icon-${index}`);

    if (textSpan.style.color === 'rgb(255, 77, 77)' || textSpan.style.color === '#ff4d4d') {
        textSpan.innerText = msg.plaintext;
        textSpan.style.color = '#00ff88';
        textSpan.style.filter = 'none';
        icon.className = 'fas fa-lock-open';
        icon.style.color = '#00ff88';
    } else {
        textSpan.innerText = msg.ciphertext;
        textSpan.style.color = '#ff4d4d';
        textSpan.style.filter = 'blur(1px)';
        icon.className = 'fas fa-lock';
        icon.style.color = '#ff4d4d';
    }
}

function renderAdminLogs() {
    const tbody = document.getElementById('adminLogTableBody');
    tbody.innerHTML = '';
    cachedMessages.forEach(m => {
        tbody.innerHTML += `<tr>
            <td>${m.timestamp}</td>
            <td>${m.sender}</td>
            <td>${m.role}</td>
            <td>${m.algo}</td>
            <td style="color:${m.can_decrypt ? '#00ff88' : '#ff4d4d'}">
                ${m.can_decrypt ? 'Çözülebilir' : 'Şifreli'}
            </td>
        </tr>`;
    });
}

function toggleAuth(target) {
    const l = document.getElementById('loginForm');
    const r = document.getElementById('registerForm');
    const t = document.getElementById('formTitle');
    if(target==='register'){l.style.display='none';r.style.display='block';t.innerText='Kayıt Ol';}
    else{l.style.display='block';r.style.display='none';t.innerText='Giriş Yap';}
}
async function logout() { await fetch(`${API_URL}/logout`, {method:'POST'}); window.location.href="/login"; }

document.addEventListener('DOMContentLoaded', () => {
    const lf = document.getElementById('loginForm');
    const rf = document.getElementById('registerForm');
    if(lf) lf.addEventListener('submit', handleLogin);
    if(rf) rf.addEventListener('submit', handleRegister);
});