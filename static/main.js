const { createApp } = Vue;
const converter = new showdown.Converter({
  noHeaderId: false,
  ghCompatibleHeaderId: true,
  parseImgDimensions: true,
  headerLevelStart: 1,
  simplifiedAutoLink: true,
  excludeTrailingPunctuationFromURLs: true,
  literalMidWordUnderscores: true,
  strikethrough: true,
  tables: true
});

createApp({
  data() {
    return {
      emails: [],
      selectedEmail: null,
      inboxSummary: null,
      loading: false,
      showConfigPanel: true,
      isEditing: false,
      editedBody: "",
      editedEmails: {}, // Store locally edited emails by ID
      // Default config values; will be updated via fetchConfig()
      config: {
        llm: { selected: "openai_gpt_4o" },
        prompt_engineering: { mode: "disabled" },
        prompt_injection_filter: { mode: "disabled" },
        "delimiter-filtering": { mode: "disabled" },
        logging: { verbose: false }
      }
    };
  },
  mounted() {
    this.fetchEmails();
    this.fetchConfig();
  },
  methods: {
    fetchEmails() {
      fetch("/api/emails")
        .then((r) => r.json())
        .then((data) => {
          this.emails = data;
        });
    },
    fetchConfig() {
      fetch("/api/config")
        .then((r) => r.json())
        .then((data) => {
          this.config = data;
        })
        .catch(err => console.error("Error fetching config:", err));
    },
    selectEmail(email) {
      this.selectedEmail = email;
      this.isEditing = false;
    },
    summarizeInbox() {
      this.loading = true;
      // Build document string including sender and subject.
      const documents = this.emails.map(email => {
        const emailBody = this.getEmailBody(email);
        return `SENDER: ${email.sender}\nSUBJECT: ${email.subject}\n\n${emailBody}`;
      });
      
      fetch("/api/summarize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ documents })
      })
        .then((r) => r.json())
        .then((data) => {
          this.inboxSummary = data.summary;
        })
        .finally(() => {
          this.loading = false;
        });
    },
    clearSummary() {
      this.inboxSummary = null;
    },
    toggleMaliciousEmail(event) {
      const endpoint = event.target.checked ? "/api/add_malicious" : "/api/remove_malicious";
      fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      })
        .then((r) => r.json())
        .then((data) => {
          console.log(data.message);
          this.fetchEmails();
        });
    },
    toggleConfigPanel() {
      this.showConfigPanel = !this.showConfigPanel;
    },
    updateConfig() {
      fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(this.config)
      })
        .then((r) => r.json())
        .then((data) => {
          console.log("Configuration updated:", data.message);
          this.config = data.config;
        })
        .catch(err => console.error("Error updating config:", err));
    },
    renderPlain(text) {
      try {
        return text.replace(/\n/g, "<br>");
      } catch (error) {
        console.error("Error rendering text:", error);
        return "";
      }
    },
    renderMarkdown(markdownText) {
      try {
        const html = converter.makeHtml(markdownText || '');
        return html.replace(/\n/g, "<br>");
      } catch (error) {
        console.error("Error rendering Markdown:", error);
        return "";
      }
    },
    
    // Email editing functionality
    startEditing() {
      if (this.selectedEmail) {
        this.editedBody = this.getEmailBody(this.selectedEmail);
        this.isEditing = true;
      }
    },
    
    saveEdits() {
      if (this.selectedEmail && this.isEditing) {
        // Store the edited body locally
        this.editedEmails[this.selectedEmail.id] = this.editedBody;
        this.isEditing = false;
      }
    },
    
    cancelEditing() {
      this.isEditing = false;
    },
    
    // Get the email body (original or edited)
    getEmailBody(email) {
      if (email && this.editedEmails.hasOwnProperty(email.id)) {
        return this.editedEmails[email.id];
      }
      return email ? email.body : "";
    },
    
    // Check if an email has been edited
    isEdited(email) {
      return email && this.editedEmails.hasOwnProperty(email.id);
    }
  }
}).mount("#app");