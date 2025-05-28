// app/static/script.js
document.addEventListener('DOMContentLoaded', () => {
    const categoryItems = document.querySelectorAll('.category-item');
    
    categoryItems.forEach(item => {
        item.addEventListener('mouseenter', () => {
            item.style.transform = 'scale(1.05)';
        });

        item.addEventListener('mouseleave', () => {
            item.style.transform = 'scale(1)';
        });
    });
});

// Обработка ошибок авторизации
document.addEventListener('DOMContentLoaded', function() {
    // Перехватываем все fetch запросы
    const originalFetch = window.fetch;
    window.fetch = function() {
        return originalFetch.apply(this, arguments)
            .then(response => {
                if (response.status === 401) {
                    // Если пользователь не авторизован, перенаправляем на страницу входа
                    window.location.href = '/login';
                    return Promise.reject('Unauthorized');
                }
                return response;
            });
    };
});
