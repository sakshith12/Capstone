class API {
    static getToken() {
        return localStorage.getItem('token');
    }
    
    static setToken(token) {
        localStorage.setItem('token', token);
    }
    
    static removeToken() {
        localStorage.removeItem('token');
    }
    
    static async request(endpoint, options = {}) {
        const url = `${CONFIG.API_BASE_URL}/api${endpoint}`;
        const token = this.getToken();
        
        const headers = options.headers || {};
        if (token && !options.skipAuth) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        const config = {
            ...options,
            headers
        };
        
        try {
            const response = await fetch(url, config);
            
            // Return response for file downloads
            if (options.responseType === 'blob') {
                return response;
            }
            
            // Parse JSON response
            const data = await response.json();
            
            // Handle 401 Unauthorized - but allow login/signup to parse the response first
            if (response.status === 401 && !options.skipAuth401Redirect) {
                this.removeToken();
                window.location.href = 'index.html';
                throw new Error('Unauthorized');
            }
            
            return data;
        } catch (error) {
            throw error;
        }
    }
    
    // Auth Endpoints
    static async signup(username, password) {
        return this.request('/auth/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            skipAuth: true,
            skipAuth401Redirect: true  // Allow signup to handle errors
        });
    }
    
    static async login(username, password) {
        return this.request('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            skipAuth: true,
            skipAuth401Redirect: true  // Allow login to handle 401 errors
        });
    }
    
    static async getCurrentUser() {
        return this.request('/auth/me');
    }
    
    // File Endpoints
    static async uploadFile(formData) {
        return this.request('/files/upload', {
            method: 'POST',
            body: formData
        });
    }
    
    static async getFileInfo(accessCode) {
        const data = await this.request(`/files/info/${accessCode}`);
        if (data.success) {
            return data.data;
        } else {
            throw new Error(data.error || 'Failed to get file info');
        }
    }
    
    static async downloadFile(accessCode) {
        const url = `${CONFIG.API_BASE_URL}/api/files/download/${accessCode}`;
        const token = this.getToken();
        
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Download failed');
        }
        
        // Get filename from Content-Disposition header
        const disposition = response.headers.get('Content-Disposition');
        let filename = 'download';
        if (disposition && disposition.includes('filename=')) {
            filename = disposition.split('filename=')[1].replace(/"/g, '');
        }
        
        // Download the file
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
    }
    
    static async getMyFiles() {
        const encodedPassword = sessionStorage.getItem('userPassword');
        const password = encodedPassword ? atob(encodedPassword) : null; // Decode from base64
        if (password) {
            return this.request('/files/my-files', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
        }
        return this.request('/files/my-files');
    }
    
    static async getSharedFiles() {
        const encodedPassword = sessionStorage.getItem('userPassword');
        const password = encodedPassword ? atob(encodedPassword) : null; // Decode from base64
        if (password) {
            return this.request('/files/shared-with-me', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
        }
        return this.request('/files/shared-with-me');
    }
    
    static async deleteFile(fileId) {
        const data = await this.request(`/files/${fileId}`, {
            method: 'DELETE'
        });
        
        if (!data.success) {
            throw new Error(data.error || 'Failed to delete file');
        }
        
        return data;
    }
    
    static async removeSharedFile(accessCode) {
        const data = await this.request(`/files/shared/${accessCode}`, {
            method: 'DELETE'
        });
        
        if (!data.success) {
            throw new Error(data.error || 'Failed to remove shared file');
        }
        
        return data;
    }
    
    // User Endpoints
    static async listUsers() {
        return this.request('/users/list');
    }
}

// Utility Functions
function showMessage(message, type = 'info') {
    const messageEl = document.getElementById('message');
    if (messageEl) {
        messageEl.textContent = message;
        messageEl.className = `message ${type}`;
        messageEl.style.display = 'block';
        
        setTimeout(() => {
            messageEl.style.display = 'none';
        }, 5000);
    }
}

function showError(message) {
    showMessage(message, 'error');
}

function showSuccess(message) {
    showMessage(message, 'success');
}

function checkAuth() {
    const token = API.getToken();
    if (!token) {
        window.location.href = 'index.html';
        return false;
    }
    return true;
}

function logout() {
    API.removeToken();
    window.location.href = 'index.html';
}
