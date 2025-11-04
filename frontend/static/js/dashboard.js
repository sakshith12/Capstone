// Dashboard JavaScript

// Check authentication on page load
window.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    loadUserFiles();
});

async function checkAuth() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'index.html';
        return;
    }

    try {
        const user = await API.getCurrentUser();
        if (user) {
            document.getElementById('username').textContent = `👤 ${user.username}`;
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        logout();
    }
}

async function loadUserFiles() {
    const loading = document.getElementById('loading');
    const error = document.getElementById('error');
    const filesList = document.getElementById('filesList');
    const noFiles = document.getElementById('noFiles');
    const filesGrid = document.getElementById('filesGrid');

    try {
        loading.style.display = 'block';
        error.style.display = 'none';

        const files = await API.getMyFiles();
        
        loading.style.display = 'none';

        if (files && files.length > 0) {
            filesList.style.display = 'block';
            noFiles.style.display = 'none';
            
            filesGrid.innerHTML = files.map(file => createFileCard(file)).join('');
        } else {
            filesList.style.display = 'none';
            noFiles.style.display = 'block';
        }
    } catch (err) {
        loading.style.display = 'none';
        error.style.display = 'block';
        error.textContent = 'Failed to load files: ' + (err.message || 'Unknown error');
    }
}

function createFileCard(file) {
    const uploadDate = new Date(file.created_at).toLocaleString();
    const expiryDate = new Date(file.expires_at).toLocaleString();
    const fileSize = formatFileSize(file.file_size);

    return `
        <div class="file-card">
            <div class="file-icon">📄</div>
            <div class="file-details">
                <h3 class="file-name">${escapeHtml(file.original_filename)}</h3>
                <p class="file-meta">Size: ${fileSize}</p>
                <p class="file-meta">Uploaded: ${uploadDate}</p>
                <p class="file-meta">Expires: ${expiryDate}</p>
                <div class="file-code">
                    <strong>Access Code:</strong> 
                    <span class="code">${file.access_code}</span>
                    <button onclick="copyCode('${file.access_code}')" class="btn btn-sm">Copy</button>
                </div>
            </div>
            <div class="file-actions">
                <button onclick="deleteFile('${file.id}', '${escapeHtml(file.original_filename)}')" 
                        class="btn btn-danger btn-sm">Delete</button>
            </div>
        </div>
    `;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyCode(code) {
    navigator.clipboard.writeText(code).then(() => {
        alert('Access code copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy code');
    });
}

async function deleteFile(fileId, filename) {
    if (!confirm(`Are you sure you want to delete "${filename}"?`)) {
        return;
    }

    try {
        await API.deleteFile(fileId);
        alert('File deleted successfully');
        loadUserFiles(); // Reload the list
    } catch (error) {
        alert('Failed to delete file: ' + (error.message || 'Unknown error'));
    }
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    window.location.href = 'index.html';
}
