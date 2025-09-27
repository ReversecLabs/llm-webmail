const { createApp } = Vue;
const converter = new showdown.Converter({ tables: true, strikethrough: true });

createApp({
  data() {
    return {
      authenticated: false,
      authMode: "login",
      user: null,
      quota: { remaining: 0, limit: 0 },
      includeMalicious: false,

      emails: [],
      selectedEmail: null,
      inboxSummary: "",
      loading: false,

      isEditing: false,
      editedBody: "",
      editedEmails: {},

      config: null,
      showConfigPanel: false,

      loginForm: { username: "", password: "" },
      registerForm: { key: "", username: "", password: "" },
      admin: {
        genCount: 5,
        keys: [],
        users: []
      },
      adminConsoleOpen: false,
      adminTab: 'users',
    };
  },
  computed: {
    isAdmin() {
      return this.user && this.user.role === "admin";
    },
  },
  methods: {
    async init() {
      const me = await this.safeJson(fetch("/api/me"));
      if (me && me.authenticated) {
        this.user = { username: me.username, role: me.role };
        this.authenticated = true;
        await this.refreshAll();
      } else {
        this.authenticated = false;
      }
    },
    async refreshAll() {
      await Promise.all([this.fetchQuota(), this.fetchConfig(), this.fetchEmails()]);
    },
    async doLogin() {
      const r = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(this.loginForm),
      });
      if (!r.ok) return alert("Invalid credentials.");
      const me = await r.json();
      this.user = me;
      this.authenticated = true;
      await this.refreshAll();
      if (this.isAdmin) {
        await Promise.all([this.fetchAdminKeys(), this.fetchUsers()]);
      }
    },
    async doRegister() {
      const r = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(this.registerForm),
      });
      if (!r.ok) {
        const j = await this.safeJson(r);
        return alert(j && j.error ? j.error : "Registration failed.");
      }
      const me = await r.json();
      this.user = me;
      this.authenticated = true;
      await this.refreshAll();
      if (this.isAdmin) {
        await Promise.all([this.fetchAdminKeys(), this.fetchUsers()]);
      }
    },
    async doLogout() {
      await fetch("/api/logout", { method: "POST" });
      this.authenticated = false;
      this.user = null;
      this.emails = [];
      this.inboxSummary = "";
      this.selectedEmail = null;
      this.admin.keys = [];
      this.admin.users = [];
    },
    async fetchQuota() {
      const j = await this.safeJson(fetch("/api/quota"));
      if (j) this.quota = j;
    },
    async fetchConfig() {
      const j = await this.safeJson(fetch("/api/config"));
      if (j) this.config = j;
    },
    async updateConfig() {
      if (!this.isAdmin) return;
      await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(this.config),
      });
    },

    async fetchEmails() {
      const url = `/api/emails?include_malicious=${this.includeMalicious ? "true" : "false"}`;
      const j = await this.safeJson(fetch(url));
      if (!j) return;
      this.emails = j.emails || j;
      if (this.selectedEmail) {
        const found = this.emails.find((e) => e.id === this.selectedEmail.id);
        if (!found) this.selectedEmail = null;
      }
    },
    toggleMaliciousEmail() {
      this.includeMalicious = !this.includeMalicious;
      this.fetchEmails();
    },

    selectEmail(email) {
      this.selectedEmail = email;
      this.isEditing = false;
      this.editedBody = "";
    },
    getEmailBody(email) {
      if (!email) return "";
      return Object.prototype.hasOwnProperty.call(this.editedEmails, email.id)
        ? this.editedEmails[email.id]
        : (email.body || "");
    },
    isEdited(email) {
      return !!(email && Object.prototype.hasOwnProperty.call(this.editedEmails, email.id));
    },
    startEditing() {
      if (!this.selectedEmail) return;
      this.editedBody = this.getEmailBody(this.selectedEmail);
      this.isEditing = true;
    },
    saveEdits() {
      if (!this.selectedEmail) return;
      this.editedEmails[this.selectedEmail.id] = this.editedBody;
      this.isEditing = false;
    },
    cancelEditing() {
      this.isEditing = false;
      this.editedBody = "";
    },

    async summarizeInbox() {
      this.loading = true;
      const documents = this.emails.map((e) => ({
        subject: e.subject,
        body: this.getEmailBody(e),
      }));
      const r = await fetch("/api/summarize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          documents: documents.map(d => `Subject: ${d.subject || ''}\n\n${d.body || ''}`)
        }),
      });
      this.loading = false;

      if (r.status === 429) {
        const j = await this.safeJson(r);
        return alert(`Daily limit reached (${j && j.limit != null ? j.limit : "limit"}).`);
      }
      if (!r.ok) return;

      const j = await r.json();
      this.inboxSummary = j.summary || j.result || "";
      await this.fetchQuota();
    },
    summarizeInboxDirect() {
      return this.summarizeInbox();
    },
    summarizeAgain() {
      return this.summarizeInbox();
    },
    clearSummary() {
      this.inboxSummary = "";
    },

    renderMarkdown(md) {
      return converter.makeHtml(md || "");
    },
    renderPlain(txt) {
      const s = (txt || "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
      return `<pre class="content">${s}</pre>`;
    },

    toggleConfigPanel() {
      this.showConfigPanel = !this.showConfigPanel;
    },

    async safeJson(promiseOrResponse) {
      try {
        const r = promiseOrResponse instanceof Response ? promiseOrResponse : await promiseOrResponse;
        return await r.json();
      } catch {
        return null;
      }
    },
    async fetchAdminKeys() {
      if (!this.isAdmin) return;
      const r = await fetch('/api/signup-keys');
      if (r.ok) this.admin.keys = await r.json();
    },
    async generateKeys() {
      if (!this.isAdmin) return;
      const count = Math.max(1, Math.min(1000, this.admin.genCount | 0 || 1));
      const r = await fetch('/api/signup-keys', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count })
      });
      if (r.ok) {
        const j = await r.json();
        // prepend newest
        const newItems = (j.tokens || []).map(t => ({ token: t, revoked: false, created_at: new Date().toISOString(), used_by: null }));
        this.admin.keys = newItems.concat(this.admin.keys);
      }
    },
    async revokeKey(token) {
      if (!this.isAdmin) return;
      await fetch('/api/signup-keys/revoke', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      // refresh list
      await this.fetchAdminKeys();
    },
    copyToken(token) {
      navigator.clipboard?.writeText(token);
    },
    async fetchUsers() {
      if (!this.isAdmin) return;
      const r = await fetch('/api/admin/users');
      if (r.ok) this.admin.users = await r.json();
    },
    async resetUserPassword(username) {
      if (!this.isAdmin) return;
      const pw = prompt(`New password for ${username}:`);
      if (!pw) return;
      const r = await fetch('/api/admin/users/reset-password', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password: pw })
      });
      if (!r.ok) alert('Failed to reset password');
    },
    async deleteUser(username) {
      if (!this.isAdmin) return;
      if (!confirm(`Delete user ${username}? This removes quota usage for that user.`)) return;
      const r = await fetch('/api/admin/users/delete', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      if (!r.ok) return alert('Failed to delete user');
      await this.fetchUsers();
    },
    openAdminConsole() {
      this.adminConsoleOpen = true;
      this.adminTab = 'users';
      if (this.isAdmin) {
        this.fetchUsers();
        this.fetchAdminKeys();
      }
    },
    closeAdminConsole() {
      this.adminConsoleOpen = false;
    },
  },
  mounted() {
    this.init();
  },
}).mount("#app");
