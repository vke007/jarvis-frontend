// JARVIS Personal AI Assistant - Frontend with API Integration
// Connects to Python Flask Backend API

class JarvisAssistantAPI {
    constructor() {
        this.API_URL = "https://jarvis-backend-production-5b50.up.railway.app/api";
        this.activeModule = 'dashboard';
        this.isListening = false;
        this.recognition = null;
        this.synthesis = window.speechSynthesis;
        this.authToken = localStorage.getItem('jarvis_token');
        this.currentUser = null;
        
        this.init();
    }
    
    async init() {
        // Check if user is logged in
        if (this.authToken) {
            await this.verifyToken();
        } else {
            this.showLoginScreen();
            return;
        }
        
        // Setup voice recognition
        this.setupVoiceRecognition();
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Load initial data
        await this.loadDashboardData();
        
        // Render initial view
        this.renderModule('dashboard');
        
        // Welcome message
        setTimeout(() => {
            this.speak(`Welcome back, ${this.currentUser.username}. JARVIS is online and ready to assist.`);
        }, 1000);
    }
    
    // ========================================================================
    // API HELPERS
    // ========================================================================
    
    async apiRequest(endpoint, method = 'GET', data = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.authToken}`
            }
        };
        
        if (data) {
            options.body = JSON.stringify(data);
        }
        
        try {
            const response = await fetch(`${this.API_URL}${endpoint}`, options);
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'API request failed');
            }
            
            return result;
        } catch (error) {
            console.error('API Error:', error);
            this.speak('Sorry, there was an error connecting to the server.');
            throw error;
        }
    }
    
    async verifyToken() {
        try {
            const result = await this.apiRequest('/auth/verify');
            this.currentUser = result.user;
            return true;
        } catch (error) {
            this.authToken = null;
            localStorage.removeItem('jarvis_token');
            this.showLoginScreen();
            return false;
        }
    }
    
    // ========================================================================
    // AUTHENTICATION
    // ========================================================================
    
    showLoginScreen() {
        document.getElementById('mainContent').innerHTML = `
            <div style="max-width: 500px; margin: 50px auto; text-align: center;">
                <h2 style="font-size: 36px; margin-bottom: 40px;">Welcome to JARVIS</h2>
                
                <div class="glass-panel" style="padding: 40px;">
                    <div id="authForm">
                        <h3 style="margin-bottom: 24px; font-size: 24px;">Login</h3>
                        
                        <input type="text" id="loginUsername" class="input-field" placeholder="Username" style="margin-bottom: 16px;">
                        <input type="password" id="loginPassword" class="input-field" placeholder="Password" style="margin-bottom: 24px;">
                        
                        <button onclick="jarvis.login()" class="btn-primary" style="width: 100%; margin-bottom: 16px;">Login</button>
                        
                        <p style="opacity: 0.7; margin: 20px 0;">Don't have an account?</p>
                        
                        <button onclick="jarvis.showRegisterForm()" class="btn-secondary" style="width: 100%;">Create Account</button>
                    </div>
                </div>
            </div>
        `;
        
        // Hide navigation
        document.getElementById('navigation').style.display = 'none';
    }
    
    showRegisterForm() {
        document.getElementById('authForm').innerHTML = `
            <h3 style="margin-bottom: 24px; font-size: 24px;">Create Account</h3>
            
            <input type="text" id="registerUsername" class="input-field" placeholder="Username" style="margin-bottom: 16px;">
            <input type="email" id="registerEmail" class="input-field" placeholder="Email" style="margin-bottom: 16px;">
            <input type="password" id="registerPassword" class="input-field" placeholder="Password" style="margin-bottom: 24px;">
            
            <button onclick="jarvis.register()" class="btn-primary" style="width: 100%; margin-bottom: 16px;">Create Account</button>
            
            <p style="opacity: 0.7; margin: 20px 0;">Already have an account?</p>
            
            <button onclick="jarvis.showLoginForm()" class="btn-secondary" style="width: 100%;">Back to Login</button>
        `;
    }
    
    showLoginForm() {
        document.getElementById('authForm').innerHTML = `
            <h3 style="margin-bottom: 24px; font-size: 24px;">Login</h3>
            
            <input type="text" id="loginUsername" class="input-field" placeholder="Username" style="margin-bottom: 16px;">
            <input type="password" id="loginPassword" class="input-field" placeholder="Password" style="margin-bottom: 24px;">
            
            <button onclick="jarvis.login()" class="btn-primary" style="width: 100%; margin-bottom: 16px;">Login</button>
            
            <p style="opacity: 0.7; margin: 20px 0;">Don't have an account?</p>
            
            <button onclick="jarvis.showRegisterForm()" class="btn-secondary" style="width: 100%;">Create Account</button>
        `;
    }
    
    async login() {
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;
        
        if (!username || !password) {
            alert('Please fill in all fields');
            return;
        }
        
        try {
            const response = await fetch(`${this.API_URL}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                alert(result.error || 'Login failed');
                return;
            }
            
            this.authToken = result.token;
            this.currentUser = result.user;
            localStorage.setItem('jarvis_token', result.token);
            
            // Reload app
            document.getElementById('navigation').style.display = 'block';
            this.init();
            
        } catch (error) {
            alert('Login failed: ' + error.message);
        }
    }
    
    async register() {
        const username = document.getElementById('registerUsername').value;
        const email = document.getElementById('registerEmail').value;
        const password = document.getElementById('registerPassword').value;
        
        if (!username || !email || !password) {
            alert('Please fill in all fields');
            return;
        }
        
        try {
            const response = await fetch(`${this.API_URL}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                alert(result.error || 'Registration failed');
                return;
            }
            
            this.authToken = result.token;
            this.currentUser = result.user;
            localStorage.setItem('jarvis_token', result.token);
            
            // Reload app
            document.getElementById('navigation').style.display = 'block';
            this.init();
            
        } catch (error) {
            alert('Registration failed: ' + error.message);
        }
    }
    
    logout() {
        this.authToken = null;
        this.currentUser = null;
        localStorage.removeItem('jarvis_token');
        this.showLoginScreen();
    }
    
    // ========================================================================
    // VOICE RECOGNITION (Same as before)
    // ========================================================================
    
    setupVoiceRecognition() {
        if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
            const SpeechRecognition = window.webkitSpeechRecognition || window.SpeechRecognition;
            this.recognition = new SpeechRecognition();
            this.recognition.continuous = true;
            this.recognition.interimResults = true;
            
            this.recognition.onresult = (event) => {
                const current = event.resultIndex;
                const transcript = event.results[current][0].transcript;
                
                document.getElementById('transcriptDisplay').style.display = 'block';
                document.getElementById('transcriptDisplay').querySelector('p').textContent = transcript;
                
                if (event.results[current].isFinal) {
                    this.processVoiceCommand(transcript);
                }
            };
            
            this.recognition.onerror = (event) => {
                console.error('Speech recognition error:', event.error);
                this.isListening = false;
                this.updateVoiceButton();
            };
        }
    }
    
    setupEventListeners() {
        document.getElementById('voiceBtn').addEventListener('click', () => {
            this.toggleVoice();
        });
        
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const module = e.target.dataset.module;
                if (module === 'logout') {
                    this.logout();
                } else if (module) {
                    this.navigateTo(module);
                }
            });
        });
    }
    
    toggleVoice() {
        if (this.isListening) {
            this.recognition.stop();
            this.isListening = false;
            document.getElementById('transcriptBox').classList.add('hidden');
            document.getElementById('transcriptDisplay').style.display = 'none';
        } else {
            this.recognition.start();
            this.isListening = true;
            document.getElementById('transcriptBox').classList.remove('hidden');
            this.speak('Listening, sir.');
        }
        this.updateVoiceButton();
    }
    
    updateVoiceButton() {
        const btn = document.getElementById('voiceBtn');
        if (this.isListening) {
            btn.classList.add('active');
            btn.textContent = '🎙️';
        } else {
            btn.classList.remove('active');
            btn.textContent = '🎤';
        }
    }
    
    speak(text) {
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1.0;
        utterance.pitch = 1.0;
        this.synthesis.speak(utterance);
    }
    
    async processVoiceCommand(command) {
        const lower = command.toLowerCase();
        
        // Module navigation
        if (lower.includes('open') || lower.includes('show')) {
            if (lower.includes('task')) return this.navigateTo('tasks');
            if (lower.includes('calendar')) return this.navigateTo('calendar');
            if (lower.includes('health')) return this.navigateTo('health');
            if (lower.includes('note')) return this.navigateTo('notes');
            if (lower.includes('code')) return this.navigateTo('code');
            if (lower.includes('setting')) return this.navigateTo('settings');
        }
        
        // Task management
        if (lower.includes('add task') || lower.includes('create task')) {
            const task = command.replace(/add task|create task|new task/gi, '').trim();
            if (task) {
                await this.createTask(task);
                this.speak('Task added successfully');
            }
            return;
        }
        
        // Use AI for general queries
        await this.aiChat(command);
    }
    
    // ========================================================================
    // DATA LOADING
    // ========================================================================
    
    async loadDashboardData() {
        try {
            this.dashboardData = await this.apiRequest('/dashboard');
        } catch (error) {
            console.error('Failed to load dashboard data');
        }
    }
    
    // ========================================================================
    // NAVIGATION & RENDERING
    // ========================================================================
    
    navigateTo(module) {
        this.activeModule = module;
        
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.module === module) {
                item.classList.add('active');
            }
        });
        
        this.renderModule(module);
    }
    
    async renderModule(module) {
        const content = document.getElementById('mainContent');
        
        switch(module) {
            case 'dashboard':
                await this.loadDashboardData();
                content.innerHTML = this.renderDashboard();
                break;
            case 'tasks':
                content.innerHTML = '<div class="loading-spinner"></div>';
                const tasks = await this.apiRequest('/tasks');
                content.innerHTML = this.renderTasks(tasks);
                this.setupTaskListeners();
                break;
            case 'calendar':
                content.innerHTML = '<div class="loading-spinner"></div>';
                const events = await this.apiRequest('/events');
                content.innerHTML = this.renderCalendar(events);
                this.setupCalendarListeners();
                break;
            case 'health':
                content.innerHTML = '<div class="loading-spinner"></div>';
                const health = await this.apiRequest('/health/today');
                content.innerHTML = this.renderHealth(health);
                this.setupHealthListeners();
                break;
            case 'notes':
                content.innerHTML = '<div class="loading-spinner"></div>';
                const notes = await this.apiRequest('/notes');
                content.innerHTML = this.renderNotes(notes);
                this.setupNotesListeners();
                break;
            case 'code':
                content.innerHTML = this.renderCodeGen();
                this.setupCodeGenListeners();
                break;
            case 'settings':
                content.innerHTML = this.renderSettings();
                this.setupSettingsListeners();
                break;
        }
    }
    
    renderDashboard() {
        const data = this.dashboardData || {};
        
        return `
            <h2 class="section-title">📊 Dashboard</h2>
            
            <div class="stats-grid">
                <div class="stat-card glass-panel" style="background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);">
                    <div class="stat-value">${data.today_events || 0}</div>
                    <div class="stat-label">Today's Events</div>
                </div>
                <div class="stat-card glass-panel" style="background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);">
                    <div class="stat-value">${data.pending_tasks || 0}</div>
                    <div class="stat-label">Pending Tasks</div>
                </div>
                <div class="stat-card glass-panel" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%);">
                    <div class="stat-value">${data.health?.steps || 0}</div>
                    <div class="stat-label">Steps Today</div>
                </div>
                <div class="stat-card glass-panel" style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);">
                    <div class="stat-value">${data.total_notes || 0}</div>
                    <div class="stat-label">Total Notes</div>
                </div>
            </div>
            
            <div class="glass-panel" style="padding: 24px; margin-top: 24px;">
                <h3 style="font-size: 20px; margin-bottom: 16px;">Quick Actions</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                    <button class="btn-secondary" onclick="jarvis.navigateTo('tasks')">📝 Add Task</button>
                    <button class="btn-secondary" onclick="jarvis.navigateTo('calendar')">📅 Add Event</button>
                    <button class="btn-secondary" onclick="jarvis.navigateTo('health')">💪 Log Health</button>
                    <button class="btn-secondary" onclick="jarvis.navigateTo('notes')">📔 New Note</button>
                </div>
            </div>
        `;
    }
    
    renderTasks(tasks) {
        return `
            <h2 class="section-title">✅ Task Management</h2>
            
            <div class="glass-panel" style="padding: 20px; margin-bottom: 20px;">
                <div style="display: flex; gap: 12px;">
                    <input type="text" id="newTaskInput" class="input-field" placeholder="Add a new task..." style="flex: 1;">
                    <button id="addTaskBtn" class="btn-primary">Add Task</button>
                </div>
            </div>
            
            <div class="glass-panel" style="padding: 24px;">
                <h3 style="font-size: 20px; font-weight: 600; margin-bottom: 16px;">All Tasks (${tasks.length})</h3>
                <div id="tasksList">
                    ${tasks.map(task => `
                        <div class="task-item" data-task-id="${task.id}">
                            <div style="display: flex; align-items: center; justify-content: space-between;">
                                <div style="display: flex; align-items: center; gap: 12px; flex: 1;">
                                    <div class="task-checkbox" style="width: 24px; height: 24px; border: 2px solid ${task.completed ? '#10b981' : 'rgba(255,255,255,0.3)'}; border-radius: 6px; background: ${task.completed ? '#10b981' : 'transparent'}; display: flex; align-items: center; justify-content: center; cursor: pointer;">
                                        ${task.completed ? '✓' : ''}
                                    </div>
                                    <span style="${task.completed ? 'text-decoration: line-through; opacity: 0.5;' : ''}">${task.text}</span>
                                </div>
                                <button class="delete-task" style="background: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer;">Delete</button>
                            </div>
                        </div>
                    `).join('') || '<p style="opacity: 0.5; text-align: center; padding: 40px;">No tasks yet. Add one above!</p>'}
                </div>
            </div>
        `;
    }
    
    renderCalendar(events) {
        return `
            <h2 class="section-title">📅 Calendar & Events</h2>
            
            <div class="glass-panel" style="padding: 20px; margin-bottom: 20px;">
                <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 16px;">Add New Event</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                    <input type="text" id="eventTitle" class="input-field" placeholder="Event title">
                    <input type="date" id="eventDate" class="input-field">
                    <input type="time" id="eventTime" class="input-field">
                    <select id="eventType" class="input-field">
                        <option value="personal">Personal</option>
                        <option value="work">Work</option>
                        <option value="college">College</option>
                        <option value="exam">Exam</option>
                        <option value="meeting">Meeting</option>
                    </select>
                </div>
                <button id="addEventBtn" class="btn-primary" style="margin-top: 12px;">Add Event</button>
            </div>
            
            <div class="glass-panel" style="padding: 24px;">
                <h3 style="font-size: 20px; font-weight: 600; margin-bottom: 16px;">All Events (${events.length})</h3>
                <div id="eventsList">
                    ${events.map(event => `
                        <div class="event-item" data-event-id="${event.id}">
                            <div style="display: flex; justify-content: space-between; align-items: start;">
                                <div>
                                    <div style="font-weight: 600; font-size: 16px;">${event.title}</div>
                                    <div style="font-size: 14px; opacity: 0.7; margin-top: 4px;">${event.date} at ${event.time}</div>
                                </div>
                                <div style="display: flex; gap: 8px; align-items: center;">
                                    <span class="badge" style="background: rgba(59, 130, 246, 0.2); color: #60a5fa;">${event.type}</span>
                                    <button class="delete-event" style="background: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer;">Delete</button>
                                </div>
                            </div>
                        </div>
                    `).join('') || '<p style="opacity: 0.5; text-align: center; padding: 40px;">No events yet. Add one above!</p>'}
                </div>
            </div>
        `;
    }
    
    renderHealth(health) {
        return `
            <h2 class="section-title">💪 Health Tracking</h2>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 24px;">
                ${this.renderHealthMetric('🚶', 'Steps', health.steps, '', 10000)}
                ${this.renderHealthMetric('💧', 'Water', health.water.toFixed(1), 'L', 3)}
                ${this.renderHealthMetric('😴', 'Sleep', health.sleep, 'hrs', 8)}
                ${this.renderHealthMetric('🔥', 'Calories', health.calories, 'kcal', 2000)}
                ${this.renderHealthMetric('❤️', 'Heart Rate', health.heart_rate || 72, 'bpm', null)}
            </div>
            
            <div class="glass-panel" style="padding: 24px;">
                <h3 style="font-size: 20px; font-weight: 600; margin-bottom: 16px;">Quick Updates</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px;">
                    <button class="btn-secondary" onclick="jarvis.updateHealthMetric('water', 0.25)">+ Water (250ml)</button>
                    <button class="btn-secondary" onclick="jarvis.updateHealthMetric('steps', 1000)">+ Steps (1000)</button>
                    <button class="btn-secondary" onclick="jarvis.updateHealthMetric('sleep', 1)">+ Sleep (1hr)</button>
                    <button class="btn-secondary" onclick="jarvis.updateHealthMetric('calories', 200)">+ Calories (200)</button>
                </div>
            </div>
        `;
    }
    
    renderHealthMetric(icon, label, value, unit, goal) {
        const progress = goal ? Math.min((value / goal) * 100, 100) : 0;
        return `
            <div class="health-metric glass-panel">
                <div style="font-size: 24px; margin-bottom: 8px;">${icon}</div>
                <div style="font-size: 12px; opacity: 0.7; margin-bottom: 4px;">${label}</div>
                <div style="font-size: 28px; font-weight: 700;">${value}<span style="font-size: 14px; opacity: 0.7;"> ${unit}</span></div>
                ${goal ? `
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${progress}%;"></div>
                    </div>
                    <div style="font-size: 12px; opacity: 0.6; margin-top: 4px;">Goal: ${goal} ${unit}</div>
                ` : ''}
            </div>
        `;
    }
    
    renderNotes(notes) {
        return `
            <h2 class="section-title">📝 Notes</h2>
            
            <div class="glass-panel" style="padding: 20px; margin-bottom: 20px;">
                <input type="text" id="noteTitle" class="input-field" placeholder="Note title" style="margin-bottom: 12px;">
                <textarea id="noteContent" class="input-field" placeholder="Write your note here..." style="min-height: 120px;"></textarea>
                <button id="addNoteBtn" class="btn-primary" style="margin-top: 12px;">Add Note</button>
            </div>
            
            <div class="grid-2">
                ${notes.map(note => `
                    <div class="glass-panel" style="padding: 20px;" data-note-id="${note.id}">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                            <h3 style="font-size: 18px; font-weight: 600; flex: 1;">${note.title}</h3>
                            <button class="delete-note" style="background: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;">Delete</button>
                        </div>
                        <p style="opacity: 0.8; white-space: pre-wrap;">${note.content}</p>
                        <div style="font-size: 12px; opacity: 0.5; margin-top: 12px;">${new Date(note.created_at).toLocaleString()}</div>
                    </div>
                `).join('') || '<p style="opacity: 0.5; text-align: center; grid-column: 1 / -1;">No notes yet. Create one above!</p>'}
            </div>
        `;
    }
    
    renderCodeGen() {
        return `
            <h2 class="section-title">💻 Code Generator</h2>
            
            <div class="glass-panel" style="padding: 24px; margin-bottom: 20px;">
                <p style="opacity: 0.7; margin-bottom: 16px;">Describe what you want to build and get AI-generated code</p>
                <textarea id="codePrompt" class="input-field" placeholder="E.g., Create a function to sort an array of objects by date..." style="min-height: 100px;"></textarea>
                <div style="display: flex; gap: 12px; margin-top: 12px;">
                    <select id="codeLanguage" class="input-field" style="max-width: 200px;">
                        <option value="python">Python</option>
                        <option value="javascript">JavaScript</option>
                        <option value="java">Java</option>
                        <option value="cpp">C++</option>
                        <option value="html">HTML/CSS</option>
                    </select>
                    <button id="generateCodeBtn" class="btn-primary">Generate Code</button>
                </div>
            </div>
            
            <div id="codeOutput" class="glass-panel" style="padding: 24px; display: none;">
                <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 16px;">Generated Code:</h3>
                <div class="code-output" id="generatedCode"></div>
                <button class="btn-secondary" style="margin-top: 12px;" onclick="jarvis.copyCode()">Copy Code</button>
            </div>
        `;
    }
    
    renderSettings() {
        return `
            <h2 class="section-title">⚙️ Settings</h2>
            
            <div class="glass-panel" style="padding: 24px; margin-bottom: 20px;">
                <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 16px;">Account Information</h3>
                <p><strong>Username:</strong> ${this.currentUser.username}</p>
                <p><strong>Email:</strong> ${this.currentUser.email}</p>
            </div>
            
            <div class="glass-panel" style="padding: 24px; margin-bottom: 20px;">
                <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 16px;">AI Configuration</h3>
                <div style="margin-bottom: 12px;">
                    <label style="display: block; margin-bottom: 6px; opacity: 0.8;">Anthropic API Key</label>
                    <input type="password" id="apiKey" class="input-field" placeholder="sk-ant-...">
                    <p style="font-size: 12px; opacity: 0.6; margin-top: 6px;">Add your API key for AI-powered features</p>
                </div>
                <button id="saveAIConfig" class="btn-primary">Save AI Configuration</button>
            </div>
            
            <div class="glass-panel" style="padding: 24px;">
                <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 16px;">Account Actions</h3>
                <button class="btn-secondary" style="background: #ef4444; border-color: #ef4444;" onclick="jarvis.logout()">🚪 Logout</button>
            </div>
        `;
    }
    
    // ========================================================================
    // EVENT LISTENERS & ACTIONS
    // ========================================================================
    
    setupTaskListeners() {
        document.getElementById('addTaskBtn')?.addEventListener('click', async () => {
            const input = document.getElementById('newTaskInput');
            if (input.value.trim()) {
                await this.createTask(input.value.trim());
                input.value = '';
                this.navigateTo('tasks');
            }
        });
        
        document.querySelectorAll('.task-checkbox').forEach(checkbox => {
            checkbox.addEventListener('click', async (e) => {
                const taskId = parseInt(e.target.closest('.task-item').dataset.taskId);
                await this.toggleTask(taskId);
                this.navigateTo('tasks');
            });
        });
        
        document.querySelectorAll('.delete-task').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const taskId = parseInt(e.target.closest('.task-item').dataset.taskId);
                await this.deleteTask(taskId);
                this.navigateTo('tasks');
            });
        });
    }
    
    setupCalendarListeners() {
        document.getElementById('addEventBtn')?.addEventListener('click', async () => {
            const title = document.getElementById('eventTitle').value;
            const date = document.getElementById('eventDate').value;
            const time = document.getElementById('eventTime').value;
            const type = document.getElementById('eventType').value;
            
            if (title && date && time) {
                await this.createEvent(title, date, time, type);
                this.navigateTo('calendar');
            }
        });
        
        document.querySelectorAll('.delete-event').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const eventId = parseInt(e.target.closest('.event-item').dataset.eventId);
                await this.deleteEvent(eventId);
                this.navigateTo('calendar');
            });
        });
    }
    
    setupHealthListeners() {
        // Health listeners handled inline
    }
    
    setupNotesListeners() {
        document.getElementById('addNoteBtn')?.addEventListener('click', async () => {
            const title = document.getElementById('noteTitle').value;
            const content = document.getElementById('noteContent').value;
            
            if (title && content) {
                await this.createNote(title, content);
                this.navigateTo('notes');
            }
        });
        
        document.querySelectorAll('.delete-note').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const noteId = parseInt(e.target.closest('[data-note-id]').dataset.noteId);
                await this.deleteNote(noteId);
                this.navigateTo('notes');
            });
        });
    }
    
    setupCodeGenListeners() {
        document.getElementById('generateCodeBtn')?.addEventListener('click', async () => {
            await this.generateCode();
        });
    }
    
    setupSettingsListeners() {
        document.getElementById('saveAIConfig')?.addEventListener('click', async () => {
            const apiKey = document.getElementById('apiKey').value;
            if (apiKey) {
                await this.apiRequest('/ai/config', 'POST', {
                    anthropic_api_key: apiKey
                });
                this.speak('AI configuration saved');
                alert('Configuration saved!');
            }
        });
    }
    
    // ========================================================================
    // API ACTIONS
    // ========================================================================
    
    async createTask(text) {
        return await this.apiRequest('/tasks', 'POST', { text });
    }
    
    async toggleTask(id) {
        // First get the task
        const tasks = await this.apiRequest('/tasks');
        const task = tasks.find(t => t.id === id);
        return await this.apiRequest(`/tasks/${id}`, 'PUT', {
            completed: !task.completed
        });
    }
    
    async deleteTask(id) {
        return await this.apiRequest(`/tasks/${id}`, 'DELETE');
    }
    
    async createEvent(title, date, time, type) {
        return await this.apiRequest('/events', 'POST', {
            title, date, time, type
        });
    }
    
    async deleteEvent(id) {
        return await this.apiRequest(`/events/${id}`, 'DELETE');
    }
    
    async createNote(title, content) {
        return await this.apiRequest('/notes', 'POST', {
            title, content
        });
    }
    
    async deleteNote(id) {
        return await this.apiRequest(`/notes/${id}`, 'DELETE');
    }
    
    async updateHealthMetric(metric, increment) {
        const health = await this.apiRequest('/health/today');
        const newValue = (health[metric] || 0) + increment;
        
        await this.apiRequest('/health', 'POST', {
            [metric]: newValue
        });
        
        this.speak(`Updated ${metric}`);
        this.navigateTo('health');
    }
    
    async generateCode() {
        const prompt = document.getElementById('codePrompt').value;
        const language = document.getElementById('codeLanguage').value;
        
        if (!prompt) return;
        
        const outputDiv = document.getElementById('codeOutput');
        const codeDiv = document.getElementById('generatedCode');
        
        outputDiv.style.display = 'block';
        codeDiv.innerHTML = '<div class="loading-spinner"></div>';
        
        try {
            const result = await this.apiRequest('/ai/code-generate', 'POST', {
                prompt,
                language
            });
            
            codeDiv.textContent = result.code;
            this.speak('Code generated successfully');
        } catch (error) {
            codeDiv.textContent = 'Error generating code. Please check your API configuration.';
        }
    }
    
    async aiChat(message) {
        try {
            const result = await this.apiRequest('/ai/chat', 'POST', { message });
            this.speak(result.response);
        } catch (error) {
            this.speak('Unable to process that request');
        }
    }
    
    copyCode() {
        const code = document.getElementById('generatedCode').textContent;
        navigator.clipboard.writeText(code);
        this.speak('Code copied to clipboard');
        alert('Code copied!');
    }
}

// Initialize the application
const jarvis = new JarvisAssistantAPI();
