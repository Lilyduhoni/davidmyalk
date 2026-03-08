async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me');
        const data = await res.json();
        return data.user;
    } catch { return null; }
}

function renderNav(currentUser, options = {}) {
    const isStore = options.isStore || false;
    const container = document.getElementById('site-nav');
    if (!container) return;

    let authHTML = '';
    let mobileAuthHTML = '';
    if (currentUser) {
        const dashLink = (currentUser.role === 'admin' || currentUser.role === 'owner') ? '/admin' : '/dashboard';
        const dashLabel = (currentUser.role === 'admin' || currentUser.role === 'owner') ? 'ADMIN' : 'DASHBOARD';
        authHTML = `
            <a href="${dashLink}" class="nav-link">${dashLabel}</a>
            <a href="#" class="nav-link" onclick="doLogout(event)" style="color:#ef4444;">LOGOUT</a>
        `;
        mobileAuthHTML = `<a href="${dashLink}" class="mobile-link" style="font-size:24px;font-family:var(--font-display);text-transform:uppercase;">Dashboard</a>`;
    } else {
        authHTML = `
            <a href="/login" class="nav-link">LOGIN</a>
            <a href="/signup" class="btn btn-primary btn-sm" style="padding:8px 20px;font-size:11px;">SIGN UP</a>
        `;
        mobileAuthHTML = `
            <a href="/login" class="mobile-link" style="font-size:24px;font-family:var(--font-display);text-transform:uppercase;">Login</a>
            <a href="/signup" class="mobile-link" style="font-size:24px;font-family:var(--font-display);text-transform:uppercase;color:var(--primary);">Sign Up</a>
        `;
    }

    const shopHref = isStore ? '#shop' : '/#shop';
    const aboutHref = isStore ? '#about' : '/#about';
    const contactHref = isStore ? '#contact' : '/#contact';

    container.innerHTML = `
        <nav class="nav-auth">
            <div class="nav-auth-inner">
                <a href="/" class="nav-brand">DAVID <span>MYALIK</span></a>
                <div class="nav-links" id="nav-desktop">
                    <a href="${shopHref}" class="nav-link">SHOP</a>
                    <a href="${aboutHref}" class="nav-link">ABOUT</a>
                    <a href="${contactHref}" class="nav-link">CONTACT</a>
                    ${authHTML}
                    ${isStore ? `
                    <button id="cart-btn" style="position:relative;background:none;border:none;color:white;cursor:pointer;" aria-label="Cart">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="21" r="1"/><circle cx="19" cy="21" r="1"/><path d="M2.05 2.05h2l2.66 12.42a2 2 0 0 0 2 1.58h9.78a2 2 0 0 0 1.95-1.57l1.65-7.43H5.12"/></svg>
                        <span id="cart-count" style="position:absolute;top:-8px;right:-8px;background:var(--primary);font-size:9px;font-weight:900;padding:2px 6px;border-radius:50%;font-family:var(--font-mono);display:none;">0</span>
                    </button>` : ''}
                </div>
                <button class="mobile-menu-toggle" id="mobile-menu-btn" aria-label="Menu">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
                </button>
            </div>
        </nav>
        <div id="mobile-menu" class="mobile-menu-overlay">
            <button id="close-menu-btn" class="mobile-close-btn">✕</button>
            <a href="${shopHref}" class="mobile-link" style="font-size:48px;font-family:var(--font-display);text-transform:uppercase;">Shop</a>
            <a href="${aboutHref}" class="mobile-link" style="font-size:48px;font-family:var(--font-display);text-transform:uppercase;">About</a>
            <a href="${contactHref}" class="mobile-link" style="font-size:48px;font-family:var(--font-display);text-transform:uppercase;">Contact</a>
            <div style="display:flex;gap:16px;margin-top:16px;">${mobileAuthHTML}</div>
        </div>
    `;

    const menuBtn = document.getElementById('mobile-menu-btn');
    const closeMenuBtn = document.getElementById('close-menu-btn');
    const mobileMenu = document.getElementById('mobile-menu');
    menuBtn.addEventListener('click', () => mobileMenu.classList.add('open'));
    function closeMobileMenu() { mobileMenu.classList.remove('open'); }
    closeMenuBtn.addEventListener('click', closeMobileMenu);
    document.querySelectorAll('.mobile-link').forEach(l => l.addEventListener('click', closeMobileMenu));
}

function renderFooter() {
    const container = document.getElementById('site-footer');
    if (!container) return;

    container.innerHTML = `
        <footer class="site-footer">
            <div class="footer-inner">
                <div class="footer-top">
                    <div>
                        <div class="footer-brand">DAVID <span class="text-red">MYALIK</span></div>
                        <p class="footer-desc">Drift culture apparel for those who live life sideways. Born from the smoke, built for the streets.</p>
                    </div>
                    <div>
                        <div class="footer-col-title">Company</div>
                        <a href="/#about" class="footer-link">About Us</a>
                        <a href="/#contact" class="footer-link">Contact</a>
                        <a href="https://www.youtube.com/@davidmyalik" target="_blank" class="footer-link">YouTube</a>
                    </div>
                    <div>
                        <div class="footer-col-title">Support</div>
                        <a href="/help-center" class="footer-link">Help Center</a>
                        <a href="/shipping-info" class="footer-link">Shipping Info</a>
                        <a href="/returns" class="footer-link">Returns & Exchanges</a>
                    </div>
                </div>
                <div class="footer-bottom">
                    <p class="footer-copy">&copy; 2026 Sideways Always. All Rights Reserved.</p>
                    <div class="footer-socials">
                        <a href="https://www.youtube.com/@davidmyalik" target="_blank" class="footer-social" aria-label="YouTube">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814z"/><path d="M9.545 15.568V8.432L15.818 12l-6.273 3.568z" fill="var(--navy-light)"/></svg>
                        </a>
                        <a href="https://instagram.com/davidmyalik" target="_blank" class="footer-social" aria-label="Instagram">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>
                        </a>
                    </div>
                </div>
            </div>
        </footer>
    `;
}

async function doLogout(e) {
    if (e) e.preventDefault();
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.href = '/';
}

function showToast(msg, type) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}
