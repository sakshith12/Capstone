// API Configuration
const CONFIG = {
    API_BASE_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:5000'
        : 'https://capstone-backend-ten-tau.vercel.app',
    MAX_FILE_SIZE: 150 * 1024 * 1024, // 150MB
    ALLOWED_EXTENSIONS: ['pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'zip', 'rar', 'mp3', 'mp4']
};
