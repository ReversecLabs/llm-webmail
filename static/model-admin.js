/* Shared Vue controls for the server-owned OpenRouter catalogue. */
const modelAdministration = {
  data() { return { modelCatalog: null, modelError: '', modelMessage: '', modelSaving: false,
    newModelId: '', newModelLabel: '', modelNotice: '', modelPoll: null, modelRefreshBusy: false }; },
  methods: {
    async loadModelCatalog() {
      this.modelError = ''; this.modelMessage = '';
      try {
        const response = await fetch('/api/admin/models');
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Could not load models');
        this.modelCatalog = data;
      } catch (error) { this.modelError = error.message; }
    },
    addModelRow() {
      const id = this.newModelId.trim(), label = this.newModelLabel.trim();
      if (!id || !label) { this.modelError = 'Enter a model ID and display name.'; return; }
      if (this.modelCatalog.models.some(m => m.model_id === id)) { this.modelError = 'That model is already listed.'; return; }
      this.modelCatalog.models.push({name: id, model_id: id, label, enabled: true});
      this.newModelId = ''; this.newModelLabel = ''; this.modelError = ''; this.modelMessage = 'Model added to the list. Save to apply.';
    },
    async saveModelCatalog() {
      this.modelSaving = true; this.modelError = ''; this.modelMessage = '';
      try {
        const response = await fetch('/api/admin/models', {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(this.modelCatalog)});
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Could not save models');
        this.modelCatalog = data; this.modelMessage = 'Saved. New requests use this catalogue; open menus refresh within two seconds.';
        await this.refreshModelOptions();
      } catch (error) { this.modelError = error.message; }
      finally {
        this.modelSaving = false;
        this.$nextTick(() => document.querySelector('.model-admin [role="alert"], .model-admin [role="status"]')?.scrollIntoView({block:'nearest'}));
      }
    },
    async refreshModelOptions() {
      if (!(this.authenticated || this.currentUser) || !this.config || this.modelRefreshBusy) return;
      this.modelRefreshBusy = true;
      try {
        const response = await fetch('/api/models');
        if (!response.ok) return;
        const data = await response.json();
        const rows = data.models;
        if ('availableLLMs' in this) this.availableLLMs = rows.map(m => ({value: m.name, label: m.label}));
        else this.config.llm.models = rows.map(m => ({name: m.name, readable_name: m.label, enabled: true}));
        if (!rows.some(m => m.name === this.config.llm.selected)) {
          this.config.llm.selected = data.default;
          const replacement = rows.find(m => m.name === data.default);
          this.modelNotice = `Your previous model is unavailable. Using ${replacement ? replacement.label : data.default}.`;
        }
      } catch (_) { /* Preserve current choices during a temporary connection failure. */ }
      finally { this.modelRefreshBusy = false; }
    }
  },
  mounted() {
    this.modelPoll = setInterval(() => this.refreshModelOptions(), 2000);
    this.modelFocusHandler = () => this.refreshModelOptions();
    window.addEventListener('focus', this.modelFocusHandler);
  },
  beforeUnmount() { clearInterval(this.modelPoll); window.removeEventListener('focus', this.modelFocusHandler); }
};
