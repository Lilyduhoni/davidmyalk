const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const pool = require('./db');

const initDatabase = require('./db-init');

const app = express();
const PORT = 5000;

initDatabase();

const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `product-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Only image files are allowed'));
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const isProduction = process.env.NODE_ENV === 'production' || !!process.env.VERCEL;
if (isProduction) {
  app.set('trust proxy', 1);
}

app.use(session({
  store: new PgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax'
  }
}));

app.use((req, res, next) => {
  res.locals.baseUrl = `${req.protocol}://${req.get('host')}`;
  next();
});

app.use(express.static(path.join(__dirname, 'public'), {
  index: false,
  extensions: []
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  if (req.session.userRole !== 'admin' && req.session.userRole !== 'owner') {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
}

app.get('/api/auth/me', async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  try {
    const result = await pool.query('SELECT id, email, first_name, last_name, role, phone, created_at FROM users WHERE id = $1', [req.session.userId]);
    if (result.rows.length === 0) return res.json({ user: null });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;
  if (!email || !password || !firstName || !lastName) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const userCount = await pool.query('SELECT COUNT(*) FROM users');
    const isFirstUser = parseInt(userCount.rows[0].count) === 0;
    const role = isFirstUser ? 'owner' : 'customer';
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, first_name, last_name, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, first_name, last_name, role',
      [email.toLowerCase(), passwordHash, firstName, lastName, role]
    );
    const user = result.rows[0];
    req.session.userId = user.id;
    req.session.userRole = user.role;
    res.json({ user, message: isFirstUser ? 'Welcome! You are the site owner.' : 'Account created successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    req.session.userId = user.id;
    req.session.userRole = user.role;
    res.json({
      user: { id: user.id, email: user.email, first_name: user.first_name, last_name: user.last_name, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const result = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) {
      return res.json({ message: 'If that email exists, a reset link has been generated.' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [result.rows[0].id, token, expiresAt]
    );
    res.json({ message: 'If that email exists, a reset link has been generated.', token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const result = await pool.query(
      'SELECT * FROM password_reset_tokens WHERE token = $1 AND used = false AND expires_at > NOW()',
      [token]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    const resetToken = result.rows[0];
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [passwordHash, resetToken.user_id]);
    await pool.query('UPDATE password_reset_tokens SET used = true WHERE id = $1', [resetToken.id]);
    res.json({ message: 'Password has been reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE is_active = true ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Product not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/orders', requireAuth, async (req, res) => {
  const { cart, shipping } = req.body;
  if (!cart || cart.length === 0) return res.status(400).json({ error: 'Cart is empty' });
  if (!shipping) return res.status(400).json({ error: 'Shipping information required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const validatedCart = [];
    for (const item of cart) {
      const product = await client.query('SELECT id, stock, price, name, image_url, is_active FROM products WHERE id = $1 FOR UPDATE', [item.id]);
      if (product.rows.length === 0 || !product.rows[0].is_active) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `Product "${item.name || 'unknown'}" is not available` });
      }
      if (product.rows[0].stock < item.qty) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `"${product.rows[0].name}" only has ${product.rows[0].stock} in stock` });
      }
      validatedCart.push({
        id: product.rows[0].id,
        name: product.rows[0].name,
        price: parseFloat(product.rows[0].price),
        image_url: product.rows[0].image_url,
        qty: parseInt(item.qty)
      });
    }

    const subtotal = validatedCart.reduce((sum, item) => sum + (item.price * item.qty), 0);
    const shippingCost = 15.00;
    const total = subtotal + shippingCost;
    const orderNumber = 'DM-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();

    const orderResult = await client.query(
      `INSERT INTO orders (user_id, order_number, subtotal, shipping_cost, total,
        shipping_first_name, shipping_last_name, shipping_address, shipping_city,
        shipping_state, shipping_zip, shipping_country)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [req.session.userId, orderNumber, subtotal, shippingCost, total,
        shipping.firstName, shipping.lastName, shipping.address, shipping.city,
        shipping.state || '', shipping.zip, shipping.country]
    );

    for (const item of validatedCart) {
      await client.query(
        `INSERT INTO order_items (order_id, product_id, product_name, product_image, quantity, price_at_purchase)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [orderResult.rows[0].id, item.id, item.name, item.image_url, item.qty, item.price]
      );
      await client.query(
        'UPDATE products SET stock = stock - $1, updated_at = NOW() WHERE id = $2',
        [item.qty, item.id]
      );
    }

    await client.query('COMMIT');
    res.json({ order: orderResult.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed to create order' });
  } finally {
    client.release();
  }
});

app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, json_agg(json_build_object(
        'id', oi.id, 'product_name', oi.product_name, 'product_image', oi.product_image,
        'quantity', oi.quantity, 'price_at_purchase', oi.price_at_purchase
      )) as items
       FROM orders o LEFT JOIN order_items oi ON o.id = oi.order_id
       WHERE o.user_id = $1
       GROUP BY o.id ORDER BY o.created_at DESC`,
      [req.session.userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, json_agg(json_build_object(
        'id', oi.id, 'product_name', oi.product_name, 'product_image', oi.product_image,
        'quantity', oi.quantity, 'price_at_purchase', oi.price_at_purchase
      )) as items
       FROM orders o LEFT JOIN order_items oi ON o.id = oi.order_id
       WHERE o.id = $1 AND o.user_id = $2
       GROUP BY o.id`,
      [req.params.id, req.session.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/user/addresses', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM addresses WHERE user_id = $1 ORDER BY is_default DESC', [req.session.userId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/user/addresses', requireAuth, async (req, res) => {
  const { firstName, lastName, addressLine1, addressLine2, city, state, zip, country, isDefault } = req.body;
  try {
    if (isDefault) {
      await pool.query('UPDATE addresses SET is_default = false WHERE user_id = $1', [req.session.userId]);
    }
    const result = await pool.query(
      `INSERT INTO addresses (user_id, first_name, last_name, address_line1, address_line2, city, state, zip, country, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [req.session.userId, firstName, lastName, addressLine1, addressLine2 || '', city, state || '', zip, country || 'US', isDefault || false]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/user/profile', requireAuth, async (req, res) => {
  const { firstName, lastName, phone } = req.body;
  try {
    const result = await pool.query(
      'UPDATE users SET first_name = $1, last_name = $2, phone = $3, updated_at = NOW() WHERE id = $4 RETURNING id, email, first_name, last_name, role, phone',
      [firstName, lastName, phone || null, req.session.userId]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/user/password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords are required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const user = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.session.userId]);
    const valid = await bcrypt.compare(currentPassword, user.rows[0].password_hash);
    if (!valid) return res.status(400).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [hash, req.session.userId]);
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [users, orders, revenue, products, lowStock, pendingOrders, recentUsers, monthlyRevenue] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM orders'),
      pool.query("SELECT COALESCE(SUM(total), 0) as total FROM orders WHERE status != 'cancelled'"),
      pool.query('SELECT COUNT(*) FROM products WHERE is_active = true'),
      pool.query('SELECT COUNT(*) FROM products WHERE is_active = true AND stock <= 10 AND stock > 0'),
      pool.query("SELECT COUNT(*) FROM orders WHERE status = 'pending'"),
      pool.query("SELECT COUNT(*) FROM users WHERE created_at > NOW() - INTERVAL '30 days'"),
      pool.query("SELECT COALESCE(SUM(total), 0) as total FROM orders WHERE status != 'cancelled' AND created_at > NOW() - INTERVAL '30 days'")
    ]);
    res.json({
      totalUsers: parseInt(users.rows[0].count),
      totalOrders: parseInt(orders.rows[0].count),
      totalRevenue: parseFloat(revenue.rows[0].total),
      totalProducts: parseInt(products.rows[0].count),
      lowStockCount: parseInt(lowStock.rows[0].count),
      pendingOrders: parseInt(pendingOrders.rows[0].count),
      newUsersThisMonth: parseInt(recentUsers.rows[0].count),
      monthlyRevenue: parseFloat(monthlyRevenue.rows[0].total)
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.phone, u.created_at,
       (SELECT COUNT(*) FROM orders WHERE user_id = u.id) as order_count
       FROM users u ORDER BY u.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/users/:id/role', requireAdmin, async (req, res) => {
  const { role } = req.body;
  if (!['customer', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  try {
    const target = await pool.query('SELECT role FROM users WHERE id = $1', [req.params.id]);
    if (target.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (target.rows[0].role === 'owner') return res.status(400).json({ error: 'Cannot change the owner role' });
    await pool.query('UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2', [role, req.params.id]);
    res.json({ message: 'Role updated' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/products', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/products', requireAdmin, async (req, res) => {
  const { name, description, price, imageUrl, category, stock } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'Name and price are required' });
  try {
    const result = await pool.query(
      `INSERT INTO products (name, description, price, image_url, category, stock)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [name, description || '', parseFloat(price), imageUrl || '', category || '', parseInt(stock) || 0]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/products/:id', requireAdmin, async (req, res) => {
  const { name, description, price, imageUrl, category, stock, isActive } = req.body;
  try {
    const result = await pool.query(
      `UPDATE products SET name = $1, description = $2, price = $3, image_url = $4,
       category = $5, stock = $6, is_active = $7, updated_at = NOW()
       WHERE id = $8 RETURNING *`,
      [name, description || '', parseFloat(price), imageUrl || '', category || '',
       parseInt(stock) || 0, isActive !== false, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Product not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/products/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE products SET is_active = false WHERE id = $1', [req.params.id]);
    res.json({ message: 'Product deactivated' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, u.email as user_email, u.first_name as user_first_name, u.last_name as user_last_name,
       json_agg(json_build_object(
        'id', oi.id, 'product_name', oi.product_name, 'product_image', oi.product_image,
        'quantity', oi.quantity, 'price_at_purchase', oi.price_at_purchase
       )) as items
       FROM orders o
       LEFT JOIN users u ON o.user_id = u.id
       LEFT JOIN order_items oi ON o.id = oi.order_id
       GROUP BY o.id, u.email, u.first_name, u.last_name
       ORDER BY o.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/orders/:id/status', requireAdmin, async (req, res) => {
  const { status, trackingNumber } = req.body;
  const validStatuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
  if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const updates = ['status = $1', 'updated_at = NOW()'];
    const values = [status];
    if (trackingNumber !== undefined) {
      updates.push(`tracking_number = $${values.length + 1}`);
      values.push(trackingNumber);
    }
    values.push(req.params.id);
    const result = await pool.query(
      `UPDATE orders SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING *`,
      values
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/upload', requireAdmin, (req, res) => {
  upload.single('image')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large (max 10MB)' });
      return res.status(400).json({ error: err.message || 'Upload failed' });
    }
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ url: `/uploads/${req.file.filename}` });
  });
});

app.get('/api/admin/categories', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != \'\' ORDER BY category');
    const defaults = ['T-Shirts', 'Hoodies', 'Hats', 'Stickers', 'Accessories', 'Posters', 'Jackets', 'Pants'];
    const existing = result.rows.map(r => r.category);
    const all = [...new Set([...defaults, ...existing])].sort();
    res.json(all);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const { firstName, lastName, email, phone, role, newPassword } = req.body;
  try {
    const target = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    if (target.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (target.rows[0].role === 'owner' && req.session.userRole !== 'owner') {
      return res.status(403).json({ error: 'Cannot edit the owner account' });
    }
    const updates = [];
    const values = [];
    let idx = 1;
    if (firstName) { updates.push(`first_name = $${idx++}`); values.push(firstName); }
    if (lastName) { updates.push(`last_name = $${idx++}`); values.push(lastName); }
    if (email) { updates.push(`email = $${idx++}`); values.push(email.toLowerCase()); }
    if (phone !== undefined) { updates.push(`phone = $${idx++}`); values.push(phone); }
    if (role && req.session.userRole === 'owner' && target.rows[0].role !== 'owner') {
      updates.push(`role = $${idx++}`); values.push(role);
    }
    if (newPassword && newPassword.length >= 6) {
      const hash = await bcrypt.hash(newPassword, 10);
      updates.push(`password_hash = $${idx++}`); values.push(hash);
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No changes provided' });
    updates.push('updated_at = NOW()');
    values.push(req.params.id);
    await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${idx}`, values);
    res.json({ message: 'User updated successfully' });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already in use' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const target = await pool.query('SELECT role FROM users WHERE id = $1', [req.params.id]);
    if (target.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (target.rows[0].role === 'owner') return res.status(403).json({ error: 'Cannot delete the owner' });
    if (parseInt(req.params.id) === req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
    const orderCheck = await pool.query('SELECT COUNT(*) FROM orders WHERE user_id = $1', [req.params.id]);
    if (parseInt(orderCheck.rows[0].count) > 0) {
      return res.status(400).json({ error: 'Cannot delete user with existing orders. Set their role to customer instead.' });
    }
    await pool.query('DELETE FROM addresses WHERE user_id = $1', [req.params.id]);
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const user = await pool.query(
      'SELECT id, email, first_name, last_name, role, phone, created_at, password_hash FROM users WHERE id = $1',
      [req.params.id]
    );
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const addresses = await pool.query('SELECT * FROM addresses WHERE user_id = $1', [req.params.id]);
    const orders = await pool.query(
      `SELECT o.*, json_agg(json_build_object(
        'product_name', oi.product_name, 'quantity', oi.quantity, 'price_at_purchase', oi.price_at_purchase
      )) as items FROM orders o
       LEFT JOIN order_items oi ON o.id = oi.order_id
       WHERE o.user_id = $1 GROUP BY o.id ORDER BY o.created_at DESC`,
      [req.params.id]
    );
    res.json({ user: user.rows[0], addresses: addresses.rows, orders: orders.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/.netlify/functions/checkout', requireAuth, async (req, res) => {
  const { cart, shipping } = req.body;
  if (!cart || cart.length === 0) return res.status(400).json({ error: 'Cart is empty' });
  try {
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_51T7aEGB9YWRWqBOnfewaL31hksdyb6ZKSsf45ErssZTwSm6OVhr8pi7FpY4CkxaIltJrhfBLF2gyCgvQ69MjidE100PsTRDw9U');
    const lineItems = cart.map(item => ({
      price_data: {
        currency: 'usd',
        product_data: { name: item.name, images: [item.img || item.image_url] },
        unit_amount: Math.round(item.price * 100),
      },
      quantity: item.qty,
    }));

    const host = req.headers.host;
    const protocol = req.headers['x-forwarded-proto'] || 'https';
    const baseUrl = `${protocol}://${host}`;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: lineItems,
      mode: 'payment',
      success_url: `${baseUrl}/#success`,
      cancel_url: `${baseUrl}/#shop`,
    });

    res.json({ url: session.url });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function serveHtmlWithOG(req, res, filePath) {
  const fs = require('fs');
  fs.readFile(filePath, 'utf8', (err, html) => {
    if (err) return res.status(500).send('Server error');
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    html = html.replace(/content="\/images\//g, `content="${baseUrl}/images/`);
    html = html.replace(/content="\/css\//g, `content="${baseUrl}/css/`);
    html = html.replace(/<meta property="og:url"[^>]*>/g, '');
    const ogUrl = `<meta property="og:url" content="${baseUrl}${req.path}">`;
    html = html.replace('</head>', `    ${ogUrl}\n</head>`);
    res.type('html').send(html);
  });
}

app.get('*', (req, res) => {
  const page = req.path.substring(1);
  const validPages = ['login', 'signup', 'forgot-password', 'reset-password', 'dashboard', 'admin', 'help-center', 'shipping-info', 'returns'];
  if (validPages.includes(page)) {
    return serveHtmlWithOG(req, res, path.join(__dirname, 'public', `${page}.html`));
  }
  serveHtmlWithOG(req, res, path.join(__dirname, 'public', 'index.html'));
});

if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}
