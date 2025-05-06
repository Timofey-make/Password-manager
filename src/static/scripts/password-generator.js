document.addEventListener('DOMContentLoaded', function() {
    const generateBtn = document.getElementById('generateBtn');

    if (generateBtn) {
        generateBtn.addEventListener('click', async function() {
            try {
                const lengthInput = document.getElementById('passLength');
                let length = parseInt(lengthInput.value) || 12;

                // Ограничиваем длину пароля от 6 до 32 символов
                length = Math.max(6, Math.min(32, length));
                lengthInput.value = length; // Обновляем значение в поле ввода

                const customWords = document.getElementById('customWords')?.value || '';
                const passwordField = document.getElementById('passwordField');

                // Генерация пароля
                const words = customWords ? customWords.split(' ') : await loadWords();
                const specialChars = ["&","#","%","$","@","1","2","3","4","5","6","7","8","9"];
                let password = '';

                while (password.length < length) {
                    const rand = Math.floor(Math.random() * 10);
                    password += rand < 4 && words.length > 0
                        ? words[Math.floor(Math.random() * words.length)]
                        : specialChars[Math.floor(Math.random() * specialChars.length)];
                }

                passwordField.value = password.substring(0, length);
            } catch (error) {
                console.error('Generation error:', error);
            }
        });
    }

    async function loadWords() {
        try {
            const response = await fetch('/static/words.json');
            return response.ok ? await response.json() : [];
        } catch (error) {
            console.error('Failed to load words:', error);
            return [];
        }
    }
});