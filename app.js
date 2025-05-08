/**
 * Network Monitor - Frontend Application
 * =====================================
 * JavaScript do obsługi interfejsu aplikacji monitorującej sieć.
 */

// Stan aplikacji
const AppState = {
    devices: [],
    currentDeviceIp: null,
    currentTimeRange: '24h',
    charts: {
        availability: null,
        history: null
    }
};

// ===================================================
// Inicjalizacja aplikacji
// ===================================================

document.addEventListener('DOMContentLoaded', () => {
    // Inicjalizacja komponentów UI
    initNavigation();
    initThemeToggle();
    
    // Pobranie danych urządzeń
    fetchDevices();
    
    // Obsługa przycisków
    initEventListeners();
    
    // Odświeżanie danych co minutę
    setInterval(() => {
        fetchDevices();
    }, 60000);
});

// ===================================================
// Obsługa nawigacji i UI
// ===================================================

function initNavigation() {
    // Przełączanie widoków
    document.getElementById('dashboard-link').addEventListener('click', (e) => {
        e.preventDefault();
        showView('dashboard');
    });
    
    document.getElementById('history-link').addEventListener('click', (e) => {
        e.preventDefault();
        showView('history');
        updateHistoryDeviceSelect();
    });
    
    document.getElementById('settings-link').addEventListener('click', (e) => {
        e.preventDefault();
        showView('settings');
    });
}

function showView(viewName) {
    // Ukrycie wszystkich widoków
    document.getElementById('dashboard-view').style.display = 'none';
    document.getElementById('history-view').style.display = 'none';
    document.getElementById('settings-view').style.display = 'none';
    
    // Pokazanie wybranego widoku
    document.getElementById(`${viewName}-view`).style.display = 'block';
    
    // Aktualizacja aktywnego linku
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.getElementById(`${viewName}-link`).classList.add('active');
}

function initThemeToggle() {
    const themeToggle = document.getElementById('theme-toggle');
    
    // Sprawdzenie zapisanego motywu
    if (localStorage.getItem('dark-mode') === 'true') {
        document.body.classList.add('dark-mode');
        themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
    }
    
    // Obsługa przełączania motywu
    themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        
        if (document.body.classList.contains('dark-mode')) {
            localStorage.setItem('dark-mode', 'true');
            themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            localStorage.setItem('dark-mode', 'false');
            themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        }
    });
}

function initEventListeners() {
    // Odświeżanie wszystkich danych
    document.getElementById('refresh-all').addEventListener('click', () => {
        fetchDevices();
        showAlert('info', 'Odświeżanie danych...');
    });
    
// Skanowanie sieci
document.getElementById('scan-network').addEventListener('click', () => {
    showAlert('info', 'Rozpoczynam skanowanie sieci...');
    scanNetwork(); // Wywołanie funkcji skanowania
});
    
    // Wyszukiwanie urządzeń
    document.getElementById('search-devices').addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        filterDevices(searchTerm);
    });
    
    // Zapisywanie ustawień
    document.getElementById('settings-form').addEventListener('submit', (e) => {
        e.preventDefault();
        saveSettings();
    });
}

// ===================================================
// Pobieranie i wyświetlanie danych
// ===================================================

function fetchDevices() {
    document.getElementById('devices-container').classList.add('loading');
    
    fetch('/api/devices')
        .then(response => response.json())
        .then(devices => {
            AppState.devices = devices;
            displayDevices(devices);
            updateDeviceStats(devices);
            document.getElementById('devices-container').classList.remove('loading');
            document.getElementById('last-scan-time').textContent = new Date().toLocaleString();
        })
        .catch(error => {
            console.error('Error fetching devices:', error);
            showAlert('danger', 'Błąd podczas pobierania danych urządzeń.');
            document.getElementById('devices-container').classList.remove('loading');
        });
}

function scanNetwork() {
    fetch('/api/scan', { method: 'POST' })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                showAlert('success', 'Skanowanie sieci zakończone sukcesem.');
                fetchDevices(); // Odśwież listę urządzeń po zakończeniu skanowania
            } else {
                showAlert('danger', 'Wystąpił błąd podczas skanowania sieci.');
            }
        })
        .catch(error => {
            console.error('Error scanning network:', error);
            showAlert('danger', 'Błąd podczas próby skanowania sieci.');
        });
}

function fetchDeviceHistory(ip) {
    fetch(`/api/devices/${ip}/history`)
        .then(response => response.json())
        .then(history => {
            displayHistory(history);
        })
        .catch(error => {
            console.error('Error fetching device history:', error);
            showAlert('danger', 'Błąd podczas pobierania historii urządzenia.');
        });
}

function displayHistory(history) {
    const container = document.getElementById('history-container');
    container.innerHTML = ''; // Wyczyszczenie kontenera

    if (history.length === 0) {
        container.innerHTML = `
            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i>
                Brak danych historycznych dla tego urządzenia.
            </div>
        `;
        return;
    }

    // Renderowanie tabeli historii
    const table = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Data</th>
                    <th>Status</th>
                    <th>Opis</th>
                </tr>
            </thead>
            <tbody>
                ${history.map(entry => `
                    <tr>
                        <td>${new Date(entry.timestamp).toLocaleString()}</td>
                        <td>${entry.status}</td>
                        <td>${entry.description || 'Brak'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    container.innerHTML = table;
}

// Wywołanie `fetchDeviceHistory` po zmianie urządzenia w selektorze
document.getElementById('history-device-select').addEventListener('change', (e) => {
    const selectedIp = e.target.value;
    if (selectedIp) {
        fetchDeviceHistory(selectedIp);
    }
});
function saveSettings() {
    const settingsForm = document.getElementById('settings-form');
    const formData = new FormData(settingsForm);

    const settings = {};
    formData.forEach((value, key) => {
        settings[key] = value;
    });

    fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
    })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                showAlert('success', 'Ustawienia zapisane pomyślnie.');
            } else {
                showAlert('danger', 'Nie udało się zapisać ustawień.');
            }
        })
        .catch(error => {
            console.error('Error saving settings:', error);
            showAlert('danger', 'Błąd podczas zapisywania ustawień.');
        });
}

function displayDevices(devices) {
    const container = document.getElementById('devices-container');
    
    // Wyczyszczenie kontenera
    container.innerHTML = '';
    
    if (devices.length === 0) {
        container.innerHTML = `
            <div class="col-12 text-center my-5">
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    Nie znaleziono żadnych urządzeń w sieci.
                </div>
            </div>
        `;
        return;
    }
    
    // Sortowanie urządzeń: najpierw offline na górze
    devices.sort((a, b) => {
        if (a.current_status === b.current_status) {
            // Jeśli mają ten sam status, sortuj po IP
            return a.ip.localeCompare(b.ip);
        }
        // Urządzenia offline na górze
        return (b.current_status || 0) - (a.current_status || 0);
    });
    
    // Generowanie kart urządzeń
    devices
