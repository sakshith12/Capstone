// Download JavaScript

let currentAccessCode = null;

window.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupDownloadForm();
});

async function checkAuth() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'index.html';
        return;
    }
}

function setupDownloadForm() {
    const form = document.getElementById('downloadForm');
    form.addEventListener('submit', handleDownloadRequest);
    
    // Auto-uppercase the access code input
    const accessCodeInput = document.getElementById('accessCode');
    accessCodeInput.addEventListener('input', (e) => {
        e.target.value = e.target.value.toUpperCase();
    });
}

async function handleDownloadRequest(e) {
    e.preventDefault();

    const accessCode = document.getElementById('accessCode').value.trim().toUpperCase();
    const downloadBtn = document.getElementById('downloadBtn');
    const downloadError = document.getElementById('downloadError');
    const fileInfo = document.getElementById('fileInfo');
    const form = document.getElementById('downloadForm');

    if (!accessCode || accessCode.length !== 6) {
        downloadError.style.display = 'block';
        downloadError.textContent = 'Please enter a valid 6-character access code';
        return;
    }

    try {
        downloadBtn.disabled = true;
        downloadBtn.textContent = 'Checking...';
        downloadError.style.display = 'none';

        // Get file info first
        const fileData = await API.getFileInfo(accessCode);
        
        currentAccessCode = accessCode;
        
        // Display file information
        document.getElementById('fileName').textContent = fileData.original_filename;
        document.getElementById('fileSize').textContent = formatFileSize(fileData.file_size);
        document.getElementById('uploader').textContent = fileData.owner_username || 'Anonymous';
        document.getElementById('expiryDate').textContent = new Date(fileData.expires_at).toLocaleString();
        
        form.style.display = 'none';
        fileInfo.style.display = 'block';

    } catch (error) {
        downloadError.style.display = 'block';
        downloadError.textContent = 'Error: ' + (error.message || 'Invalid access code or file not found');
        downloadBtn.disabled = false;
        downloadBtn.textContent = 'Download File';
    }
}

async function confirmDownload() {
    const downloadProgress = document.getElementById('downloadProgress');
    const downloadSuccess = document.getElementById('downloadSuccess');
    const downloadError = document.getElementById('downloadError');
    const fileInfo = document.getElementById('fileInfo');

    try {
        fileInfo.style.display = 'none';
        downloadProgress.style.display = 'block';
        downloadError.style.display = 'none';

        // Simulate progress
        let progress = 0;
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        const progressInterval = setInterval(() => {
            progress += 5;
            if (progress <= 90) {
                progressFill.style.width = progress + '%';
                progressText.textContent = `Downloading... ${progress}%`;
            }
        }, 200);

        // Download file
        await API.downloadFile(currentAccessCode);

        // Complete progress
        clearInterval(progressInterval);
        progressFill.style.width = '100%';
        progressText.textContent = 'Download complete!';

        // Show success
        setTimeout(() => {
            downloadProgress.style.display = 'none';
            downloadSuccess.style.display = 'block';
        }, 500);

    } catch (error) {
        downloadProgress.style.display = 'none';
        downloadError.style.display = 'block';
        downloadError.textContent = 'Download failed: ' + (error.message || 'Unknown error');
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function resetDownload() {
    document.getElementById('downloadForm').reset();
    document.getElementById('downloadForm').style.display = 'block';
    document.getElementById('fileInfo').style.display = 'none';
    document.getElementById('downloadSuccess').style.display = 'none';
    document.getElementById('downloadError').style.display = 'none';
    document.getElementById('progressFill').style.width = '0%';
    document.getElementById('downloadBtn').disabled = false;
    document.getElementById('downloadBtn').textContent = 'Download File';
    currentAccessCode = null;
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    window.location.href = 'index.html';
}
