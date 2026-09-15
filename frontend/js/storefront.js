/**
 * CyberMart E-Commerce Storefront (Target Testbed Controller)
 * Provides interactive manual injection testing against live endpoints.
 */

window.Storefront = {
  products: [],

  init() {
    this.setupSearch();
    this.setupReviewForm();
    this.setupSSRFPreview();
    this.setupCSRFTransfer();
    this.setupIDORLookup();
    this.setupResetDB();
  },

  async loadProducts() {
    try {
      const resp = await fetch('/api/shop/products');
      const data = await resp.json();
      if (data.status === 'success') {
        this.products = data.products;
        this.renderProducts(data.products);
      }
    } catch (e) {
      console.warn('Failed to load shop products:', e);
    }
  },

  renderProducts(list) {
    const container = document.getElementById('shop-products-grid');
    if (!container) return;

    container.innerHTML = list.map(p => `
      <div class="product-item">
        <div>
          <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">${escapeHtml(p.category)}</div>
          <div class="product-name">${escapeHtml(p.name)}</div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">${escapeHtml(p.description)}</div>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-top: 8px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 8px;">
          <span style="text-decoration: line-through; color: var(--text-muted); font-size: 12px;">$${p.price.toFixed(2)}</span>
          <span class="product-price">$${p.discount_price.toFixed(2)}</span>
        </div>
      </div>
    `).join('');
  },

  setupSearch() {
    const searchInput = document.getElementById('store-search-input');
    const searchBtn = document.getElementById('store-search-btn');

    if (searchBtn) {
      searchBtn.addEventListener('click', () => {
        const q = searchInput ? searchInput.value : '';
        this.executeSearch(q);
      });
    }

    if (searchInput) {
      searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          this.executeSearch(searchInput.value);
        }
      });
    }
  },

  async executeSearch(query) {
    const resultsBox = document.getElementById('store-response-output');
    try {
      const resp = await fetch(`/api/shop/search?q=${encodeURIComponent(query)}`);
      const data = await resp.json();

      if (resultsBox) {
        resultsBox.textContent = JSON.stringify(data, null, 2);
        resultsBox.style.color = resp.status === 403 ? 'var(--neon-red)' : '#10b981';
      }

      if (data.results) {
        this.renderProducts(data.results);
      }
    } catch (e) {
      if (resultsBox) {
        resultsBox.textContent = `Error: ${e.message}`;
        resultsBox.style.color = 'var(--neon-red)';
      }
    }
  },

  injectSearchPayload(payload) {
    const input = document.getElementById('store-search-input');
    if (input) {
      input.value = payload;
      this.executeSearch(payload);
    }
  },

  setupReviewForm() {
    const submitBtn = document.getElementById('btn-submit-review');
    if (submitBtn) {
      submitBtn.addEventListener('click', async () => {
        const comment = document.getElementById('review-comment-input').value;
        const resultsBox = document.getElementById('store-response-output');
        
        try {
          const resp = await fetch('/api/shop/reviews', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ product_id: 1, author: 'Shopper_99', comment: comment, rating: 5 })
          });
          const data = await resp.json();
          if (resultsBox) {
            resultsBox.textContent = JSON.stringify(data, null, 2);
            resultsBox.style.color = resp.status === 403 ? 'var(--neon-red)' : '#10b981';
          }
        } catch (e) {
          if (resultsBox) resultsBox.textContent = `Error: ${e.message}`;
        }
      });
    }
  },

  injectReviewPayload(payload) {
    const input = document.getElementById('review-comment-input');
    if (input) {
      input.value = payload;
      document.getElementById('btn-submit-review').click();
    }
  },

  setupSSRFPreview() {
    const fetchBtn = document.getElementById('btn-fetch-ssrf');
    if (fetchBtn) {
      fetchBtn.addEventListener('click', async () => {
        const url = document.getElementById('ssrf-url-input').value;
        const resultsBox = document.getElementById('store-response-output');

        try {
          const resp = await fetch('/api/shop/fetch-preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
          });
          const data = await resp.json();
          if (resultsBox) {
            resultsBox.textContent = JSON.stringify(data, null, 2);
            resultsBox.style.color = resp.status === 403 ? 'var(--neon-red)' : '#10b981';
          }
        } catch (e) {
          if (resultsBox) resultsBox.textContent = `Error: ${e.message}`;
        }
      });
    }
  },

  injectSSRFPayload(url) {
    const input = document.getElementById('ssrf-url-input');
    if (input) {
      input.value = url;
      document.getElementById('btn-fetch-ssrf').click();
    }
  },

  setupCSRFTransfer() {
    const transferBtn = document.getElementById('btn-test-csrf');
    if (transferBtn) {
      transferBtn.addEventListener('click', async () => {
        const resultsBox = document.getElementById('store-response-output');
        try {
          const resp = await fetch('/api/shop/transfer-points', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ recipient_username: 'attacker_wallet', amount: 250 })
          });
          const data = await resp.json();
          if (resultsBox) {
            resultsBox.textContent = JSON.stringify(data, null, 2);
            resultsBox.style.color = resp.status === 403 ? 'var(--neon-red)' : '#10b981';
          }
        } catch (e) {
          if (resultsBox) resultsBox.textContent = `Error: ${e.message}`;
        }
      });
    }
  },

  setupIDORLookup() {
    const idorBtn = document.getElementById('btn-test-idor');
    if (idorBtn) {
      idorBtn.addEventListener('click', async () => {
        const orderId = document.getElementById('idor-order-id').value;
        const resultsBox = document.getElementById('store-response-output');
        try {
          const resp = await fetch(`/api/shop/orders/${orderId}`);
          const data = await resp.json();
          if (resultsBox) {
            resultsBox.textContent = JSON.stringify(data, null, 2);
            resultsBox.style.color = resp.status === 403 ? 'var(--neon-red)' : '#10b981';
          }
        } catch (e) {
          if (resultsBox) resultsBox.textContent = `Error: ${e.message}`;
        }
      });
    }
  },

  setupResetDB() {
    const resetBtn = document.getElementById('btn-reset-store-db');
    if (resetBtn) {
      resetBtn.addEventListener('click', async () => {
        await fetch('/api/shop/reset', { method: 'POST' });
        this.loadProducts();
        const resultsBox = document.getElementById('store-response-output');
        if (resultsBox) {
          resultsBox.textContent = 'Store database reset to original seed state.';
          resultsBox.style.color = 'var(--neon-cyan)';
        }
      });
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  window.Storefront.init();
});
