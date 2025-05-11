// Main JavaScript for Password Manager

// Wait for DOM to be loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('Password Manager web interface loaded');
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});