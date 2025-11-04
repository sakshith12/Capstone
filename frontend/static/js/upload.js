// Upload JavaScript

window.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupUploadForm();
});

async function checkAuth() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'index.html';
        return;
    }
}

function setupUploadForm() {
    const form = document.getElementById('uploadForm');
    form.addEventListener('submit', handleUpload);
}

async function handleUpload(e) {
    e.preventDefault();

    const fileInput = document.getElementById('fileInput');
    const expiryTime = document.getElementById('expiryTime').value;
    const recipientUsername = document.getElementById('recipientUsername').value.trim();
    const uploadBtn = document.getElementById('uploadBtn');
    const uploadProgress = document.getElementById('uploadProgress');
    const uploadSuccess = document.getElementById('uploadSuccess');
    const uploadError = document.getElementById('uploadError');
    const form = document.getElementById('uploadForm');

    if (!fileInput.files || fileInput.files.length === 0) {
        uploadError.style.display = 'block';
        uploadError.textContent = 'Please select a file';
        return;
    }

    const file = fileInput.files[0];

    // Validate file size (150MB)
    const maxSize = 150 * 1024 * 1024;
    if (file.size > maxSize) {
        uploadError.style.display = 'block';
        uploadError.textContent = 'File size exceeds 150MB limit';
        return;
    }

    try {
        // Show progress
        form.style.display = 'none';
        uploadProgress.style.display = 'block';
        uploadError.style.display = 'none';
        uploadSuccess.style.display = 'none';

        // Simulate progress
        let progress = 0;
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        const progressInterval = setInterval(() => {
            progress += 5;
            if (progress <= 90) {
                progressFill.style.width = progress + '%';
                progressText.textContent = `Uploading... ${progress}%`;
            }
        }, 200);

        // Upload file
        const result = await API.uploadFile(file, expiryTime, recipientUsername);

        // Complete progress
        clearInterval(progressInterval);
        progressFill.style.width = '100%';
        progressText.textContent = 'Upload complete!';

        // Show success
        setTimeout(() => {
            uploadProgress.style.display = 'none';
            uploadSuccess.style.display = 'block';
            document.getElementById('accessCode').textContent = result.access_code;
        }, 500);

    } catch (error) {
        form.style.display = 'block';
        uploadProgress.style.display = 'none';
        uploadError.style.display = 'block';
        uploadError.textContent = 'Upload failed: ' + (error.message || 'Unknown error');
    }
}

function copyAccessCode() {
    const code = document.getElementById('accessCode').textContent;
    navigator.clipboard.writeText(code).then(() => {
        alert('Access code copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy code');
    });
}

function resetUpload() {
    document.getElementById('uploadForm').reset();
    document.getElementById('uploadForm').style.display = 'block';
    document.getElementById('uploadSuccess').style.display = 'none';
    document.getElementById('uploadError').style.display = 'none';
    document.getElementById('progressFill').style.width = '0%';
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    window.location.href = 'index.html';
}
